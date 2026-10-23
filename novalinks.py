#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Novalinks (com.gpn.android.alpha) 订阅抓取
------------------------------------------
官方 API: https://api.novalinks.cloud  (GPN Backend, FastAPI, /openapi.json 公开)

流程:
  1. POST /api/v1/auth/guest       游客注册, 送 24h 试用 (trial_minutes=1440)
  2. GET  /api/v1/subscription/url 换取订阅链接 (sub_xxx, 30 天有效)
  3. GET  <订阅链接>                拿到完整 mihomo/clash 配置 (10 个节点)
  4. 可选 --probe                  用 xray 逐个实测出口, 剔除死节点

用法:
  python3 novalinks.py                 # 抓取并写入 yaml/txt
  python3 novalinks.py --probe         # 额外实测节点可用性
  python3 novalinks.py --stats         # 只看当前账号状态
"""

import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
import urllib.error
import urllib.request

API = "https://api.novalinks.cloud"
APP_VERSION = "2.17.10"
UA = "okhttp/4.12.0"
STATE = os.environ.get("NOVA_STATE", "novalinks_state.json")
OUT_YAML = os.environ.get("NOVA_YAML", "novalinks_sub.yaml")
OUT_TXT = os.environ.get("NOVA_TXT", "novalinks_nodes.txt")
XRAY_BIN = os.environ.get("XRAY_BIN", "xray")
# 距离过期多少小时就重新注册 (试用 24h)
REFRESH_HOURS = float(os.environ.get("NOVA_REFRESH_HOURS", "8"))

MODELS = [
    "Pixel 7", "Pixel 8", "SM-S9180", "SM-G9910", "2201123C", "V2227A",
    "RMX3706", "PGT-AN10", "M2102J2SC", "iPhone14,5", "CPH2451", "NE2210",
]


def log(*a):
    print(*a, flush=True)


def http(url, method="GET", body=None, headers=None, timeout=25):
    h = {"User-Agent": UA, "Accept": "application/json"}
    if headers:
        h.update(headers)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # 连接被重置等
        return 0, str(e)


def load_state():
    try:
        with open(STATE) as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(st):
    st["updated_at"] = int(time.time())
    with open(STATE, "w") as f:
        json.dump(st, f, ensure_ascii=False, indent=1)


def register_guest():
    """游客登录, 返回 (token, device_id, resp)"""
    for attempt in range(4):
        dev = uuid.uuid4().hex
        body = {
            "device_id": dev,
            "platform": "android",
            "device_model": random.choice(MODELS),
            "signup_source": "android_gpn",
            "app_version": APP_VERSION,
            "country": os.environ.get("NOVA_COUNTRY", "HK"),
        }
        code, txt = http(API + "/api/v1/auth/guest", "POST", body)
        if code == 200:
            try:
                d = json.loads(txt)
                if d.get("token"):
                    return d["token"], dev, d
            except Exception:
                pass
        log(f"  guest 注册失败 [{code}] {txt[:120]}  ({attempt + 1}/4)")
        time.sleep(2 + attempt * 3)
    return None, None, None


def fetch_sub_url(token):
    """换取订阅链接 (sub_xxx token, 30 天)"""
    for _ in range(3):
        code, txt = http(API + "/api/v1/subscription/url", headers={"Authorization": "Bearer " + token})
        if code == 200:
            try:
                return json.loads(txt).get("url")
            except Exception:
                pass
        time.sleep(2)
    return None


def account_status(token):
    """GET /api/v1/subscription -> 状态字典"""
    code, txt = http(API + "/api/v1/subscription", headers={"Authorization": "Bearer " + token})
    if code == 200:
        try:
            return json.loads(txt)
        except Exception:
            pass
    return {}


def claim_ad_reward(token, unit="ca-app-pub-3940256099942544/5224354917"):
    """
    免广告领 30 分钟。
    服务端不校验 AdMob SSV, 空 body 也直接返回 granted;
    serve_token/served_at 只是反作弊“可选”字段, 不填不影响发放。
    30 分钟内重复领取返回 outcome=window_dedup (不叠加, 但 adAccess 保持有效)。
    """
    body = {
        "adProvider": "admob",
        "adUnitId": unit,
        "rewardType": "vpn_time",
        "rewardAmount": 30,
        "client_request_id": uuid.uuid4().hex,
    }
    code, txt = http(API + "/api/v1/ad/reward", "POST", body,
                     headers={"Authorization": "Bearer " + token})
    try:
        d = json.loads(txt)
    except Exception:
        d = {"raw": txt}
    d["_http"] = code
    return d


# ---------- clash <-> vless uri ----------

def _stream_query(p):
    """按协议生成 vless uri 的 query 参数"""
    q = {"encryption": "none", "type": p.get("network", "tcp")}
    if p.get("tls"):
        q["security"] = "reality" if p.get("reality-opts") else "tls"
        sni = p.get("servername") or p.get("sni")
        if sni:
            q["sni"] = sni
        if p.get("client-fingerprint"):
            q["fp"] = p["client-fingerprint"]
        if p.get("skip-cert-verify"):
            q["allowInsecure"] = "1"
        ro = p.get("reality-opts") or {}
        if ro.get("public-key"):
            q["pbk"] = ro["public-key"]
        if ro.get("short-id"):
            q["sid"] = ro["short-id"]
    else:
        q["security"] = "none"
    if p.get("flow"):
        q["flow"] = p["flow"]
    if p.get("network") == "ws":
        wo = p.get("ws-opts") or {}
        q["path"] = wo.get("path", "/")
        host = (wo.get("headers") or {}).get("Host")
        if host:
            q["host"] = host
    elif p.get("network") == "grpc":
        go = p.get("grpc-opts") or {}
        q["serviceName"] = go.get("grpc-service-name", "")
    return q


def to_vless_uri(p, tag):
    from urllib.parse import urlencode, quote
    q = _stream_query(p)
    return "vless://%s@%s:%s?%s#%s" % (
        p["uuid"], p["server"], p["port"], urlencode(q, quote_via=quote), quote(tag)
    )


def parse_yaml_proxies(text):
    """不依赖 PyYAML 的极简代理块解析 (订阅里只有 proxies 段需要)"""
    try:
        import yaml
        d = yaml.safe_load(text)
        return d.get("proxies") or []
    except Exception:
        pass
    proxies, cur, in_block = [], None, False
    for line in text.splitlines():
        if re.match(r"^proxies:\s*$", line):
            in_block = True
            continue
        if in_block and re.match(r"^[a-zA-Z-]+:\s*$", line):
            break
        if not in_block:
            continue
        m = re.match(r"^- name:\s*(.+)$", line)
        if m:
            cur = {"name": m.group(1).strip().strip('"\'')}
            proxies.append(cur)
            continue
        if cur is None:
            continue
        m = re.match(r"^\s+([a-z-]+):\s*(.+)$", line)
        if m:
            k, v = m.group(1), m.group(2).strip().strip('"\'')
            if k == "port":
                try:
                    v = int(v)
                except Exception:
                    pass
            cur[k] = v
    return proxies


def probe(proxies, budget=6):
    """用 xray 逐节点测出口 IP。返回可用 name 集合"""
    if not os.path.exists(XRAY_BIN) and not shutil_which(XRAY_BIN):
        log("  [probe] 未找到 xray, 跳过实测")
        return None
    ok_names = set()
    port = 10900
    for p in proxies:
        conf = {
            "log": {"loglevel": "error"},
            "inbounds": [{"port": port, "listen": "127.0.0.1", "protocol": "socks",
                          "settings": {"udp": False, "auth": "noauth"}}],
            "outbounds": [_to_outbound(p)],
        }
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(conf, f)
        proc = subprocess.Popen([XRAY_BIN, "run", "-c", path],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5)
        info = ""
        for attempt in range(2):
            try:
                r = subprocess.run(
                    ["curl", "-s", "-m", str(budget), "--socks5-hostname", f"127.0.0.1:{port}",
                     "http://ip-api.com/json/?fields=status,country,city,query"],
                    capture_output=True, text=True, timeout=budget + 5)
                d = json.loads(r.stdout) if r.stdout.strip().startswith("{") else {}
                if d.get("status") == "success":
                    ok_names.add(p["name"])
                    info = f'{d.get("query")} {d.get("country")}'
                    break
            except Exception:
                pass
            time.sleep(0.5)
        proc.terminate()
        try:
            proc.wait(3)
        except Exception:
            proc.kill()
        os.unlink(path)
        log(f'  [probe] {"OK  " if p["name"] in ok_names else "FAIL"} {p["name"]:<22} {info}')
    return ok_names


def shutil_which(b):
    from shutil import which
    return which(b)


def _to_outbound(p):
    net = p.get("network", "tcp")
    ss = {"network": net}
    sni = p.get("servername") or p.get("sni") or ""
    if p.get("reality-opts"):
        ro = p["reality-opts"]
        ss["security"] = "reality"
        ss["realitySettings"] = {"serverName": sni, "publicKey": ro.get("public-key"),
                                 "shortId": ro.get("short-id", ""),
                                 "fingerprint": p.get("client-fingerprint", "chrome")}
    elif p.get("tls"):
        ss["security"] = "tls"
        ss["tlsSettings"] = {"serverName": sni, "fingerprint": p.get("client-fingerprint", "chrome"),
                             "allowInsecure": bool(p.get("skip-cert-verify", False))}
    else:
        ss["security"] = "none"
    if net == "ws":
        wo = p.get("ws-opts") or {}
        ss["wsSettings"] = {"path": wo.get("path", "/"), "headers": wo.get("headers") or {}}
    u = {"id": p["uuid"], "encryption": "none"}
    if p.get("flow"):
        u["flow"] = p["flow"]
    return {"protocol": "vless",
            "settings": {"vnext": [{"address": p["server"], "port": int(p["port"]), "users": [u]}]},
            "streamSettings": ss}


def tag_name(p, idx):
    cc = (p.get("country_code") or "").upper()
    n = p.get("name", f"node{idx}")
    n = re.sub(r"^Novalinks-", "", n)
    return f"NL-{n}" if not n.startswith("NL-") else n


def main():
    args = sys.argv[1:]
    do_probe = "--probe" in args
    stats_only = "--stats" in args
    st = load_state()

    # ---- 账号 ----
    token = st.get("token")
    exp = st.get("expires_at", 0)
    need_new = (not token) or (exp - time.time() < REFRESH_HOURS * 3600)
    if need_new:
        log("[1] 游客注册 (24h 试用)")
        token, dev, resp = register_guest()
        if not token:
            log("注册失败, 退出")
            return 1
        sub = (resp or {}).get("subscription") or {}
        trial_min = sub.get("trial_minutes_remaining") or 1440
        st = {"token": token, "device_id": dev, "user_id": resp.get("user_id"),
              "trial_minutes": trial_min, "expires_at": int(time.time()) + trial_min * 60,
              "created_at": int(time.time())}
        save_state(st)
        log(f"    user_id={st['user_id']} 试用 {trial_min} 分钟")
    else:
        log(f"[1] 复用账号 user_id={st.get('user_id')} 剩余 {(exp - time.time()) / 3600:.1f}h")

    # ---- 时长兜底: 试用将尽 -> 免广告领 30 分钟 ----
    force_ad = "--ad" in args
    stt = account_status(token)
    remain = stt.get("remainingTrialSeconds") or 0
    if force_ad or (not stt.get("canUseVpn")) or (0 < remain < 1800):
        r = claim_ad_reward(token)
        log(f"[1b] 免广告领时长: {r.get('outcome')} {r.get('adRewardMinutes')}min "
            f"canUseVpn={r.get('canUseVpn')}")
        if not r.get("canUseVpn") and not stt.get("canUseVpn"):
            log("    广告额度也没了, 换新账号")
            token, dev, resp = register_guest()
            if token:
                sub = (resp or {}).get("subscription") or {}
                trial_min = sub.get("trial_minutes_remaining") or 1440
                st = {"token": token, "device_id": dev, "user_id": resp.get("user_id"),
                      "trial_minutes": trial_min,
                      "expires_at": int(time.time()) + trial_min * 60,
                      "created_at": int(time.time())}
                save_state(st)
                log(f"    新账号 user_id={st['user_id']} 试用 {trial_min} 分钟")

    # ---- 订阅链接 ----
    sub_url = st.get("sub_url")
    if not sub_url or st.get("sub_expires", 0) < time.time() + 86400:
        sub_url = fetch_sub_url(token)
        if sub_url:
            st["sub_url"] = sub_url
            st["sub_expires"] = int(time.time()) + 29 * 86400
            save_state(st)
    if not sub_url:
        log("拿不到订阅链接")
        return 2
    log("[2] 订阅链接: " + sub_url)

    # ---- 拉配置 ----
    code, yml = http(sub_url)
    if code != 200 or "proxies:" not in yml:
        log(f"拉取配置失败 [{code}] {yml[:200]}")
        return 3
    proxies = parse_yaml_proxies(yml)
    log(f"[3] 解析到 {len(proxies)} 个节点")

    if stats_only:
        for p in proxies:
            log(f"    {p.get('name')}  {p.get('server')}:{p.get('port')}  {p.get('network')}/{p.get('tls') and 'tls'}")
        code, txt = http(API + "/api/v1/subscription", headers={"Authorization": "Bearer " + token})
        log("[4] 账号状态: " + txt[:400])
        return 0

    # ---- 实测 ----
    if do_probe and proxies:
        log("[4] 实测节点 (xray)")
        ok = probe(proxies)
        if ok is not None:
            dropped = [p["name"] for p in proxies if p["name"] not in ok]
            if "--keep-dead" in args:
                log(f"    未测通但保留 {len(dropped)} 个: {', '.join(dropped)}")
            else:
                proxies = [p for p in proxies if p["name"] in ok]
                if dropped:
                    log(f"    剔除 {len(dropped)} 个: {', '.join(dropped)}")
    if not proxies:
        log("没有可用节点, 保留上一次输出")
        return 4

    # ---- 输出 ----
    # yaml 原样落盘 (服务端配置本身合法, 重写容易引入缩进/类型问题)
    if do_probe and len(proxies) < len(parse_yaml_proxies(yml)):
        # 实测有剔除时, 需要过滤 proxies 段, 交给 yaml 库处理
        yml = _filter_yaml(yml, proxies)
    with open(OUT_YAML, "w") as f:
        f.write(yml)

    uris = []
    for i, p in enumerate(proxies):
        tag = tag_name(p, i)
        uris.append(to_vless_uri(p, tag))
    with open(OUT_TXT, "w") as f:
        f.write("\n".join(uris) + "\n")

    log(f"[5] 已写出 {OUT_YAML} / {OUT_TXT}: {len(proxies)} 个节点")
    for i, p in enumerate(proxies):
        log(f"    - {tag_name(p, i):<22} {p.get('server')}:{p.get('port')}")
    return 0


def _filter_yaml(text, keep):
    """实测剔除后重建 yaml (保留其它字段)"""
    import yaml as _y
    d = _y.safe_load(text)
    names = {p["name"] for p in keep}
    d["proxies"] = keep
    for g in d.get("proxy-groups", []) or []:
        if isinstance(g.get("proxies"), list):
            g["proxies"] = [n for n in g["proxies"]
                            if n in names or n in ("DIRECT", "REJECT", "PASS", "COMPATIBLE")]
    return _y.safe_dump(d, allow_unicode=True, sort_keys=False, default_flow_style=False, width=4096)


if __name__ == "__main__":
    sys.exit(main())
