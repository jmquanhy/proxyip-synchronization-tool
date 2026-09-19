#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cf_proxyip_sync.py — Cloudflare ProxyIP 扫描 + DNS 同步（自研版，零第三方依赖）

流程（完全按你的需求）：
  1. 从 ranges/<region>.txt 读取候选网段（CIDR）
  2. 每批随机抽 BATCH 个 IP（默认 100），并发调测速接口
  3. 能通且归属目标地区(colo)的留下来；不通就再抽新一批继续
  4. 直到每个地区凑够 TARGET 个（默认 3）有效 IP
  5. 同步到 Cloudflare DNS：
        region.<你的域名>  每个地区 3 条 A 记录（TTL 60，直连不代理）

用法：
  python cf_proxyip_sync.py                          # 只扫描，存 ips-v4.txt
  python cf_proxyip_sync.py --batch 100 --target 3   # 每批100个，每地区凑3个

Cloudflare 同步凭据（环境变量，缺省则跳过同步只扫描）：
  CF_API_TOKEN   受限 API Token（推荐，权限 Zone.DNS:Edit 即可）
  CF_ZONE_ID     域名 Zone ID
  （兼容旧式：CF_EMAIL + CF_API_KEY = Global API Key）

依赖：仅 Python 3.9+ 标准库（urllib / ipaddress / concurrent.futures）。
"""
import argparse
import ipaddress
import json
import os
import random
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RANGES_DIR = os.path.join(BASE_DIR, "ranges")

# 测速接口：从环境变量读取，不要把私有接口 URL 写进公开代码库
# 可用 --check-url 参数覆盖；缺省时必须 CF_CHECK_URL 环境变量
CHECK_API = os.environ.get("CF_CHECK_URL", "").strip()

# 地区 → Cloudflare colo 代码映射
# HK=香港 HKG / JP=日本 NRT,ITM,KIX,FUK,OKA,SPK / US=美国各机房
COLO_TO_REGION = {"HKG": "HK", "SIN": "SG"}
JP_COLOS = {"NRT", "ITM", "KIX", "FUK", "OKA", "SPK"}
for _c in JP_COLOS:
    COLO_TO_REGION[_c] = "JP"
US_COLOS = {
    "SJC", "LAX", "SEA", "PDX", "DEN", "DFW", "DAL", "AUS", "IAH", "MCI",
    "MSP", "ORD", "STL", "MEM", "ATL", "MIA", "JAX", "BNA", "IAD", "DCA",
    "EWR", "JFK", "BOS", "PHX", "SLC", "LAS", "OKC", "TUS", "CLT", "RDU",
    "PIT", "CLE", "DTW", "IND", "CMH", "VPS", "BUF", "ABQ", "TUL", "OMA",
}
for _c in US_COLOS:
    COLO_TO_REGION[_c] = "US"


def load_cidrs(region):
    """读取 ranges/<region>.txt，返回 ipaddress.ip_network 列表。

    文件名查找不区分大小写：兼容 HK.txt / hk.txt / HK.TXT 各种命名
    （GitHub Actions 的 Linux runner 区分大小写，必须处理）。
    """
    path = os.path.join(RANGES_DIR, region.lower() + ".txt")
    if not os.path.exists(path) and os.path.isdir(RANGES_DIR):
        base_wanted = region.lower()
        for fn in sorted(os.listdir(RANGES_DIR)):
            base, ext = os.path.splitext(fn)
            if ext.lower() == ".txt" and base.lower() == base_wanted:
                path = os.path.join(RANGES_DIR, fn)
                break
    if not os.path.exists(path):
        print(f"[跳过] 缺少 {path}，请把地区 {region} 的网段放进去")
        return []
    nets = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            line = line.split("#")[0].strip()
            line = line.split(",")[0].strip()
            try:
                nets.append(ipaddress.ip_network(line, strict=False))
            except ValueError as e:
                print(f"[警告] 忽略非法网段 {line!r}: {e}")
    print(f"[{region}] 载入 {len(nets)} 个网段（{path}）")
    return nets


def sample_ips(nets, count):
    """按"地址空间大小"加权，从全部网段里随机抽 count 个 IP。"""
    if not nets:
        return []
    # 用网段内的地址总数做权重（/24=256，/16=65536……），避免小网段被高估
    weighted = []
    for net in nets:
        weight = max(1, net.num_addresses)
        weighted.extend([net] * min(weight, 256))
    ips = set()
    guard = 0
    while len(ips) < count and guard < count * 50:
        guard += 1
        net = random.choice(weighted if len(weighted) < 10_000 else nets)
        if net.num_addresses == 0:
            continue
        host = random.randrange(net.num_addresses)
        ips.add(str(net[host]))
    return list(ips)


def parse_check_response(body, ip):
    """从 /check 响应里提取 (成功?, 地区, 延迟ms)。"""
    try:
        data = json.loads(body)
    except Exception:
        return None
    if data.get("success") is not True:
        return None
    pr = data.get("probe_results") or {}
    v4 = pr.get("ipv4") or {}
    exit_ = v4.get("exit") or {}
    colo = str(exit_.get("colo") or "").upper().strip()
    if colo not in COLO_TO_REGION:
        # 顶层 colo 是探测器机房，不能用来定地区；只有 exit.colo 才是目标 IP 的归属
        return None
    latency = v4.get("tls_ms") or v4.get("connect_ms") or v4.get("http_ms")
    if latency is None:
        latency = data.get("responseTime")
    try:
        latency = int(latency)
    except (TypeError, ValueError):
        latency = 9999
    return {"ip": ip, "region": COLO_TO_REGION[colo], "colo": colo, "latency": latency}


def check_ip(ip, base_url, timeout=10):
    """测一个 IP，成功返回解析结果；请求级失败返回 {'ip','error',...}。

    返回值区分两种失败：
      - None            ：接口判定该 IP 无效（success=false/地区不匹配）
      - {'error': 原因} ：请求本身失败（超时/连接失败/HTTP错误）
    """
    url = base_url.format(ip=ip)
    req = urllib.request.Request(url, headers={"User-Agent": "cf-proxyip-sync/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
        return parse_check_response(body, ip)
    except socket.timeout:
        return {"ip": ip, "error": "超时"}
    except urllib.error.URLError as e:
        reason = getattr(e, "reason", None)
        if isinstance(reason, socket.timeout):
            return {"ip": ip, "error": "超时"}
        return {"ip": ip, "error": f"连接失败({reason})"}
    except Exception as e:
        return {"ip": ip, "error": f"异常({type(e).__name__})"}


def _err_summary(results):
    """统计一批结果里的请求级失败原因，返回可打印文本。"""
    from collections import Counter
    c = Counter()
    for r in results:
        if isinstance(r, dict) and "error" in r:
            err = str(r["error"])
            key = "超时" if "超时" in err else err.split("(")[0][:12]
            c[key] += 1
    if not c:
        return "无请求失败"
    return " ".join(f"{k}:{v}" for k, v in c.items())


def retest_ips(ips, base_url, timeout, workers):
    """重测一批存量 IP（增量模式用），返回按延迟排序的有效结果。

    对探活失败的 IP 重试 1 次，抗接口抖动（慢响应不代表 IP 失效）。
    """
    if not ips:
        return []

    def run_batch(batch_ips):
        with ThreadPoolExecutor(max_workers=min(workers, len(batch_ips))) as ex:
            futs = {ex.submit(check_ip, ip, base_url, timeout): ip for ip in batch_ips}
            return [fut.result() for fut in as_completed(futs)]

    def valid_of(res):
        return [r for r in res if isinstance(r, dict) and "error" not in r and r]

    def err_of(res):
        return [r for r in res if isinstance(r, dict) and "error" in r]

    results = run_batch(ips)
    errors_first = err_of(results)
    if errors_first:
        print(f"[探活] 首轮请求失败 {len(errors_first)} 个（{_err_summary(errors_first)}），重试 1 次")
    ok0 = {r["ip"] for r in valid_of(results)}
    dead = [ip for ip in ips if ip not in ok0]
    retry = run_batch(dead) if dead else []
    still_err = err_of(retry)
    if still_err:
        print(f"[探活] 重试后仍失败 {len(still_err)} 个（{_err_summary(still_err)}）")
    ok = valid_of(results) + valid_of(retry)
    ok.sort(key=lambda r: r["latency"])
    return ok


def load_previous_state():
    """从 ips-v4.txt 恢复上次的每地区 (IP, colo) 列表（增量模式的缓存）。"""
    state = {}
    path = os.path.join(BASE_DIR, "ips-v4.txt")
    if not os.path.exists(path):
        return state
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split("#")
            ip = parts[0].strip()
            colo = parts[1].strip().upper() if len(parts) > 1 else ""
            if colo in COLO_TO_REGION:
                state.setdefault(COLO_TO_REGION[colo], []).append((ip, colo))
    return state


def scan_region(region, nets, batch, target, base_url, workers, timeout=10, max_attempts=50):
    """对单个地区循环抽批测试，直到凑够 target 个有效 IP。

    max_attempts：批次上限。补扫用较小的值（快速止损），全量用默认。
    """
    found = []
    attempt = 0
    seen = set()
    while len(found) < target:
        attempt += 1
        batch_ips = [ip for ip in sample_ips(nets, batch) if ip not in seen]
        if not batch_ips:
            print(f"[{region}] 抽不出新 IP 了，停止")
            break
        seen.update(batch_ips)
        print(f"[{region}] 第 {attempt} 批：抽取 {len(batch_ips)} 个 IP 测试中……")
        t0 = time.time()
        results = []
        results_all = []   # 所有接口判定成功的（含非目标地区），用于诊断出口分布
        errors = []
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(check_ip, ip, base_url, timeout): ip for ip in batch_ips}
            for fut in as_completed(futs):
                r = fut.result()
                if isinstance(r, dict) and "error" in r:
                    errors.append(r)
                elif isinstance(r, dict):
                    results_all.append(r)
                    if r["region"] == region:
                        results.append(r)
        results.sort(key=lambda r: r["latency"])
        new = results[: target - len(found)]
        found.extend(new)
        for r in new:
            print(f"[{region}] ← {r['ip']}  {r['colo']}  {r['latency']}ms")
        # 诊断：本批所有成功 IP 的出口机房分布（看清非目标地区到底出口在哪）
        dist = {}
        for r in results_all:
            dist[r["colo"]] = dist.get(r["colo"], 0) + 1
        dist_txt = " ".join(f"{k}:{v}" for k, v in sorted(dist.items())) if dist else "无"
        err_txt = _err_summary(errors) if errors else ""
        print(f"[{region}] 本批成功 {len(results_all)} 个，目标命中 {len(results)}，"
              f"出口分布 [{dist_txt}]" + (f"，请求失败 {_err_summary(errors)}" if errors else "")
              + f"，累计 {len(found)}/{target}（耗时 {time.time()-t0:.1f}s）")
        if attempt >= max_attempts:
            print(f"[{region}] 达到最大轮次限制（{max_attempts} 批），停止")
            break
    return found


def sync_to_cloudflare(region, base_domain, ips, api_token, zone_id, cf_email=None, cf_api_key=None):
    """把该地区 top-N IP 同步为 region.<base_domain> 的 A 记录。"""
    name = f"{region}.{base_domain}"
    headers_base = {
        "Content-Type": "application/json",
        "User-Agent": "cf-proxyip-sync/1.0",
    }
    if api_token:
        headers_base["Authorization"] = f"Bearer {api_token}"
    elif cf_email and cf_api_key:
        headers_base["X-Auth-Email"] = cf_email
        headers_base["X-Auth-Key"] = cf_api_key
    else:
        return False

    def api(method, path, body=None):
        url = f"https://api.cloudflare.com/client/v4{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, headers=headers_base, method=method)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))

    print(f"[同步] {name}: 现有记录查询中……")
    try:
        existing = api("GET", f"/zones/{zone_id}/dns_records?type=A&name={name}")["result"]
    except Exception as e:
        print(f"[同步] 查询失败: {e}")
        return False

    existing_map = {r["content"]: r["id"] for r in existing}
    desired = [i["ip"] for i in ips]

    deleted = []
    for ip_val, rec_id in existing_map.items():
        if ip_val not in desired:
            try:
                api("DELETE", f"/zones/{zone_id}/dns_records/{rec_id}")
                deleted.append(ip_val)
                print(f"[同步] 删除过期 {ip_val}")
            except Exception as e:
                print(f"[同步] 删除 {ip_val} 失败: {e}")

    added = []
    for ip_val in desired:
        if ip_val not in existing_map:
            try:
                api("POST", f"/zones/{zone_id}/dns_records",
                    {"type": "A", "name": name, "content": ip_val, "ttl": 60, "proxied": False})
                added.append(ip_val)
                print(f"[同步] 新增 {name} → {ip_val}")
            except Exception as e:
                print(f"[同步] 新增 {ip_val} 失败: {e}")

    if not deleted and not added:
        print(f"[同步] {name} 与现有记录完全一致，无需变更（0 次写入）")
    else:
        print(f"[同步] {name} 完成：新增 {len(added)} 条，删除 {len(deleted)} 条")
    return True


def _lat_mark(ms):
    """延迟标记：🟢<150ms / 🟡150~300ms / 🔴>=300ms / 🔴=失效。

    注意：GitHub 会剥离 HTML style 属性，用 emoji 才能在 Summary 里显示颜色。
    """
    try:
        ms = int(ms)
    except (TypeError, ValueError):
        return "🔴 -"
    if ms == 9999:
        return "🔴 失效"
    if ms < 150:
        return f"🟢 {ms}ms"
    if ms < 300:
        return f"🟡 {ms}ms"
    return f"🔴 {ms}ms"


def _src_mark(src):
    """来源标记：有效🟢 / 新增🔵 / 失效🔴。"""
    if src.startswith("✔"):
        return f"🟢 {src}"
    if src.startswith("➕"):
        return f"🔵 {src}"
    if src.startswith("✘") or src.startswith("❌"):
        return f"🔴 **{src}**"
    return src


def write_summary(stats, args, can_sync, summary_path):
    """把本次运行结果写成 Markdown 表格，追加到 GitHub Step Summary。

    summary_path：None 时用 GITHUB_STEP_SUMMARY 环境变量（Actions 自动注入）；
    本地测试可 --summary <文件> 指定。
    """
    path = summary_path or os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    stamp = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")

    lines = []
    lines.append(f"## CF ProxyIP 运行报告（{stamp}）")
    if not stats:
        lines.append("> 本次未产生任何结果（探活+补扫全失败，已保留昨日缓存）。")
    else:
        lines.append("")
        lines.append("### 各地区状态")
        lines.append("| 地区 | 子域名 | 存量有效 | 失效 | 补扫 | 最终 IP（延迟）| DNS 同步 |")
        lines.append("|:---|:---|:---:|:---:|:---:|:---|:---:|")
        for r in stats:
            sub = f"{r['region'].lower()}.{args.domain}" if args.domain else "-"
            kept = r["kept"]
            dead = r["dead"]
            added = r["added"]
            dns = r["dns"]
            ips_txt = " ".join(
                f"`{i['ip']}` {_lat_mark(i['latency'])}" for i in r["best"]
            ) if r["best"] else "🔴 —"
            if kept and not dead and not added:
                act = f"🟢 **全部有效，无需扫描**"
            elif added:
                act = f"🔵 替换 {dead} 个，新增 {added} 个"
            else:
                act = f"🔴 **补扫不足，保留现状**"
            dead_cell = f"🔴 **{dead}**" if dead else str(dead)
            lines.append(
                f"| {r['region']} | `{sub}` | {kept} / 3 | {dead_cell} | {act} | {ips_txt} | {dns} |"
            )
        lines.append("")
        lines.append("### IP 明细")
        lines.append("| IP | 地区 | Colo | 延迟 | 来源 |")
        lines.append("|:---|:---:|:---:|:---:|:---|")
        for r in stats:
            for i in r["detail"]:
                lat_cell = _lat_mark(i["latency"]) if i["latency"] is not None else "🔴 失效"
                lines.append(
                    f"| `{i['ip']}` | {i['region']} | {i['colo']} | {lat_cell} | {_src_mark(i['src'])} |"
                )
        if not can_sync:
            lines.append("")
            lines.append("> 未配置 CF 凭据/域名，本次仅扫描、未同步 DNS。")
    lines.append("")
    lines.append("<sub>Powered by cf-proxyip-sync · 增量模式：存量探活，失效才补扫</sub>")
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except Exception as e:
        print(f"[警告] Summary 写入失败: {e}")


def main():
    ap = argparse.ArgumentParser(description="CF ProxyIP 扫描 + DNS 同步")
    ap.add_argument("--regions", default="HK,JP,US", help="地区列表，逗号分隔（默认 HK,JP,US）")
    ap.add_argument("--domain", default=os.environ.get("CF_TARGET_DOMAIN", ""), help="主域名，如 your-domain.com（子域名自动拼接）")
    ap.add_argument("--batch", type=int, default=100, help="每批随机抽多少个 IP 测试（默认 100）")
    ap.add_argument("--target", type=int, default=3, help="每个地区凑几个有效 IP（默认 3）")
    ap.add_argument("--workers", type=int, default=40, help="每地区并发测速线程数（默认 40）")
    ap.add_argument("--timeout", type=int, default=10, help="单 IP 测速超时秒数（默认 10）")
    ap.add_argument("--full", action="store_true", help="强制全量扫描（默认增量：先探活上次的 IP，失效才补扫）")
    ap.add_argument("--summary", default="", help="运行报告写入路径（默认 GITHUB_STEP_SUMMARY，Actions 自动注入）")
    ap.add_argument("--check-url", default=CHECK_API, help="测速接口模板")
    args = ap.parse_args()

    check_url = args.check_url or CHECK_API
    if not check_url:
        print("[错误] 未设置测速接口：请在环境变量 CF_CHECK_URL 中配置，或用 --check-url 传入（示例 https://你的.worker.dev/check?proxyip={ip}）")
        sys.exit(2)

    api_token = os.environ.get("CF_API_TOKEN", "")
    zone_id = os.environ.get("CF_ZONE_ID", "")
    cf_email = os.environ.get("CF_EMAIL", "")
    cf_api_key = os.environ.get("CF_API_KEY", "")
    can_sync = bool(api_token or (cf_email and cf_api_key)) and bool(zone_id) and bool(args.domain)
    if not can_sync:
        print("[提示] 缺少 CF 凭据/域名，本次只扫描不同步（输出 ips-v4.txt）")

    regions = [r.strip().upper() for r in args.regions.split(",") if r.strip()]

    all_best = {}
    stats = []
    lock = threading.Lock()
    prev_state = {} if args.full else load_previous_state()

    def _scan_region(region):
        nets = load_cidrs(region)
        if not nets:
            return
        # 增量模式：先探活上次的 IP，有效就复用，缺额才补扫
        cached = prev_state.get(region, [])
        cached_ips = [ip for ip, _ in cached]
        valid = []
        if cached and not args.full:
            print(f"[{region}] 探活上次 {len(cached)} 个存量 IP ……")
            # 探活只有几个请求，超时放宽到 30s：GHA(美国)→接口(欧洲)链路慢，
            # 慢响应不代表 IP 失效（本地实测同批 IP 全通）
            valid = retest_ips(cached_ips, check_url, max(args.timeout, 30), args.workers)
            for r in valid:
                print(f"[{region}] ✔ 存量有效 {r['ip']}  {r['colo']}  {r['latency']}ms")
            dead = [ip for ip in cached_ips if ip not in {x["ip"] for x in valid}]
            for ip in dead:
                print(f"[{region}] ✘ 存量失效 {ip}，需要补")
            missing = args.target - len(valid)
            if missing <= 0:
                print(f"[{region}] 存量 {len(valid)} 个全部有效，无需扫描")
                best = valid[:args.target]
            else:
                print(f"[{region}] 存量有效 {len(valid)} 个，缺 {missing} 个，补扫中……")
                new = scan_region(region, nets, args.batch, missing, check_url, args.workers, args.timeout, max_attempts=6)
                combined = sorted(valid + new, key=lambda x: x["latency"])
                best = combined[:args.target]
                if len(best) < args.target:
                    print(f"[警告] {region} 补扫后仍只有 {len(best)}/{args.target} 个有效 IP，"
                          f"该地区将保持现状不更新 DNS（避免写入过时记录）")
        else:
            best = scan_region(region, nets, args.batch, args.target, check_url, args.workers, args.timeout, max_attempts=12)
            if len(best) < args.target:
                print(f"[警告] {region} 全量扫描仅得到 {len(best)}/{args.target} 个有效 IP")
        if best:
            with lock:
                all_best[region] = best
        elif cached and not args.full:
            # 单地区保护：探活+补扫都失败但昨日有缓存时，保留缓存条目（不写 DNS，
            # 只保住 ips-v4.txt 里的缓存，下次继续增量探活，避免地区从文件消失）
            print(f"[警告] {region} 探活/补扫均失败，保留昨日 {len(cached)} 个缓存 IP（不更新 DNS）")
            best = [{"ip": ip, "region": region, "colo": colo, "latency": 9999} for ip, colo in cached]
            with lock:
                all_best[region] = best
        if best:
            # 记录统计信息（供 Actions Summary 表格）
            valid_ips = {x["ip"] for x in valid}
            detail = []
            seen_ips = set()
            for x in best:
                if x["latency"] == 9999:
                    detail.append({**x, "src": "✘ 已失效，保留缓存"})
                elif x["ip"] in valid_ips:
                    detail.append({**x, "src": "✔ 存量有效"})
                else:
                    detail.append({**x, "src": "➕ 补扫新增"})
                seen_ips.add(x["ip"])
            # 明细表里补上"本次确认失效、未留下"的 IP 行（红色）
            for ip in cached_ips:
                if ip not in seen_ips:
                    detail.append({"ip": ip, "region": region, "colo": "-", "latency": None, "src": "✘ 已失效，未保留"})
            dead_ips = [ip for ip in cached_ips if ip not in valid_ips]
            stats.append({
                "region": region,
                "kept": len([x for x in best if x["ip"] in valid_ips]),
                "dead": len(dead_ips),
                "added": len([x for x in best if x["ip"] not in valid_ips and x["latency"] != 9999]),
                "best": best,
                "detail": detail,
                "dns": "⏭ 跳过(未配)" if not can_sync else "…待同步",
            })

    # 三个地区并行扫描（互不等待，总时长 ≈ 最慢的地区）
    with ThreadPoolExecutor(max_workers=len(regions)) as ex:
        for region in regions:
            ex.submit(_scan_region, region)

    if not all_best:
        # 全灭保护：增量模式下探活+补扫全失败，多半是探测通道异常而非 IP 全挂，
        # 保留昨日缓存，跳过本轮更新（不覆盖 ips-v4.txt、不改 DNS、退出码 0 不报红）
        if prev_state and not args.full:
            print("[警告] 探活+补扫全部失败（疑似探测通道异常，如接口抖动/网络慢），保留昨日缓存，跳过本轮更新")
            for region, entries in prev_state.items():
                all_best[region] = [
                    {"ip": ip, "region": region, "colo": colo, "latency": 9999}
                    for ip, colo in entries
                ]
            print("本次无有效更新，直接收工（未改动 ips-v4.txt / DNS）")
            write_summary([], args, can_sync, args.summary or None)
            return
        print("没有扫到任何有效 IP。")
        sys.exit(1)

    # 输出 ips-v4.txt（兼容 IP#地区 格式）
    out_path = os.path.join(BASE_DIR, "ips-v4.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        for region, ips in all_best.items():
            for r in ips:
                f.write(f"{r['ip']}#{r['colo']}\n")
    stamp = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n已保存 {out_path}（{stamp}）")

    if can_sync:
        for region, ips in all_best.items():
            ok = sync_to_cloudflare(region.lower(), args.domain, ips, api_token, zone_id, cf_email, cf_api_key)
            for s in stats:
                if s["region"] == region:
                    s["dns"] = "✅ 已同步" if ok else "❌ 失败"

    write_summary(stats, args, can_sync, args.summary or None)


if __name__ == "__main__":
    main()