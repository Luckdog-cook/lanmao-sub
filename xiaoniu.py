#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
小牛VPN (com.xiaoniu.goolge v1.0.9.2) 节点抓取
================================================
API:   https://e3h5ydd.com  (动态域名数组: e3h5ydd/t9r5sre/cfmnfr6/4dcs3n8.com)
流程:  guest/auth(游客注册, mach_code 随机) → guest/trialVip(试用VIP)
       → subscribe/subscribe → trial_subscribe 订阅URL → base64 vless 清单
说明:  节点绑定账号(sub_uuid/uuid随账号变), 试用VIP = 200限速 + 1TB 流量
输出:  xiaoniu_sub.txt(base64) / xiaoniu_nodes.txt(链接) / xiaoniu_clash.yaml
"""
import base64, json, os, random, string, subprocess, sys, tempfile, time
import urllib.request
from urllib.parse import urlparse, parse_qs, quote, unquote

BASES = ["https://e3h5ydd.com", "https://t9r5sre.com",
         "https://cfmnfr6.com", "https://4dcs3n8.com"]
OUT_DIR = os.environ.get("XN_OUT", ".")
STATE = os.environ.get("XN_STATE", "xiaoniu_state.json")
PROBE = "--probe" in sys.argv
XRAY = os.environ.get("XRAY_BIN", "xray")

def http(base, method, path, body=None, headers=None, timeout=20):
    h = {"Content-Type": "application/json", "User-Agent": "okhttp/4.9.0",
         "Platform": "1", "Version": "1.0.9.2", "ClientCode": "XIAONIUFREE",
         "ChannelCode": "XNYAOQING1", "PackageName": "com.xiaoniu.goolge",
         "Lang": "zh"}
    if headers: h.update(headers)
    req = urllib.request.Request(base + path,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers=h, method=method)
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, str(e)

def new_machine():
    return str(random.getrandbits(128))

def register():
    mc = new_machine()
    for base in BASES:
        code, txt = http(base, "POST", "/api/v1/guest/auth",
                         {"mach_code": mc},
                         {"MachCode": mc})
        try: d = json.loads(txt)
        except Exception: continue
        if d.get("code") == 20000 and d.get("data", {}).get("guest_token"):
            print(f"[1] 游客注册成功 (base={base}) uid={d['data'].get('guest_user_id')}")
            print(f"    试用时长字段 timeout={d['data'].get('timeout')}s")
            return base, mc, d["data"]
    print("[x] 全部域名注册失败")
    return None, None, None

def load_state():
    try:
        return json.load(open(STATE))
    except Exception:
        return {}

def save_state(d):
    d["created_at"] = int(time.time())
    json.dump(d, open(STATE, "w"), ensure_ascii=False, indent=1)

def try_existing(st):
    """复用已有游客号: 返回 (base, mc, sub_url) 或 None"""
    mc, gt = st.get("mach_code"), st.get("guest_token")
    if not mc or not gt: return None
    H = {"MachCode": mc, "GuestToken": gt}
    for base in BASES:
        code, txt = http(base, "GET", "/api/v1/subscribe/subscribe", None, H)
        try: d = json.loads(txt)
        except Exception: continue
        if d.get("code") == 20000:
            sub = (d.get("data") or {}).get("trial_subscribe") or (d.get("data") or {}).get("guest_subscribe") or {}
            if sub.get("subscribe_url"):
                print(f"[1] 复用现有游客号 uid≈{st.get('guest_user_id','?')} "
                      f"(已用 {(time.time()-st.get('created_at',0))/86400:.1f} 天)")
                return base, mc, sub["subscribe_url"]
        print(f"    {base} 复用失败: {d.get('msg','')[:60]}")
    return None

def main():
    st = load_state()
    reuse = try_existing(st)
    if reuse:
        base, mc, url = reuse
        gt = st["guest_token"]
    else:
        base, mc, data = register()
        if not base: return 1
        gt = data["guest_token"]
        st = {"mach_code": mc, "guest_token": gt,
              "guest_user_id": data.get("guest_user_id")}
        save_state(st)
        H = {"MachCode": mc, "GuestToken": gt}
        code, txt = http(base, "POST", "/api/v1/guest/trialVip", {}, H)
        print(f"[2] 领取试用VIP: {json.loads(txt).get('msg') if txt.startswith('{') else txt[:80]}")
        code, txt = http(base, "GET", "/api/v1/subscribe/subscribe", None, H)
        d = json.loads(txt).get("data") or {}
        sub = d.get("trial_subscribe") or d.get("guest_subscribe") or {}
        url = sub.get("subscribe_url")
        if not url:
            print("[x] 新号也没拿到订阅:", txt[:150]); return 1
    print(f"[3] 订阅链接: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "okhttp/4.9.0"})
    raw = urllib.request.urlopen(req, timeout=25).read()
    links = [l for l in base64.b64decode(raw + b"=" * (-len(raw) % 4)).decode("utf-8", "replace").splitlines() if l.strip()]
    print(f"[4] 拉到 {len(links)} 个节点")

    if PROBE:
        links = probe(links)
        print(f"[5] 实测可用 {len(links)} 个")

    if not links:
        print("[x] 没有可用节点"); return 1

    with open(f"{OUT_DIR}/xiaoniu_nodes.txt", "w") as f:
        f.write("\n".join(links) + "\n")
    with open(f"{OUT_DIR}/xiaoniu_sub.txt", "wb") as f:
        f.write(base64.b64encode("\n".join(links).encode()))
    clash = ["port: 7890", "mode: rule", "log-level: info",
             "unified-delay: true", "tcp-concurrent: true",
             "proxies:"]
    names = []
    for i, uri in enumerate(links):
        u = urlparse(uri); q = {k: v[0] for k, v in parse_qs(u.query).items()}
        tag = unquote(uri.split("#")[-1]) if "#" in uri else f"xn-{i}"
        names.append(tag)
        p = {"name": tag, "type": "vless", "server": u.hostname, "port": u.port or 443,
             "uuid": u.username, "udp": True, "tls": q.get("security") in ("tls", "reality"),
             "client-fingerprint": q.get("fp", "chrome")}
        if q.get("flow"): p["flow"] = q["flow"]
        if q.get("security") == "reality":
            p["servername"] = q.get("sni", u.hostname)
            p["reality-opts"] = {"public-key": q.get("pbk", ""), "short-id": q.get("sid", "")}
        elif q.get("sni"): p["servername"] = q["sni"]
        if q.get("type") == "ws":
            p["network"] = "ws"; p["ws-opts"] = {"path": q.get("path", "/")}
        clash.append("  - " + json.dumps(p, ensure_ascii=False))
    clash.append("proxy-groups:")
    clash.append("  - name: 🚀 节点选择")
    clash.append("    type: select")
    clash.append("    proxies:")
    clash += [f"      - {n}" for n in names]
    clash.append("  - name: ♻️ 自动选择")
    clash.append("    type: url-test")
    clash.append("    url: http://www.gstatic.com/generate_204")
    clash.append("    interval: 300")
    clash.append("    proxies:")
    clash += [f"      - {n}" for n in names]
    clash.append("rules:")
    clash.append("  - GEOSITE,cn,DIRECT")
    clash.append("  - GEOIP,CN,DIRECT,no-resolve")
    clash.append(f"  - MATCH,🚀 节点选择")
    with open(f"{OUT_DIR}/xiaoniu_clash.yaml", "w") as f:
        f.write("\n".join(clash) + "\n")
    print(f"[6] 已写出 xiaoniu_sub.txt / xiaoniu_nodes.txt / xiaoniu_clash.yaml")
    return 0

def probe(links):
    from concurrent.futures import ThreadPoolExecutor
    def one(i, uri):
        u = urlparse(uri); q = {k: v[0] for k, v in parse_qs(u.query).items()}
        ss = {"network": q.get("type", "tcp")}
        if q.get("security") == "reality":
            ss["security"] = "reality"
            ss["realitySettings"] = {"serverName": q.get("sni", u.hostname),
                                     "publicKey": q.get("pbk", ""), "shortId": q.get("sid", ""),
                                     "fingerprint": q.get("fp", "chrome")}
        elif q.get("security") == "tls":
            ss["security"] = "tls"
            ss["tlsSettings"] = {"serverName": q.get("sni", u.hostname), "fingerprint": "chrome"}
        usr = {"id": u.username, "encryption": "none"}
        if q.get("flow"): usr["flow"] = q["flow"]
        conf = {"log": {"loglevel": "error"},
                "inbounds": [{"port": 12900 + i, "listen": "127.0.0.1", "protocol": "socks",
                              "settings": {"udp": False}}],
                "outbounds": [{"protocol": "vless",
                               "settings": {"vnext": [{"address": u.hostname, "port": u.port or 443,
                                                       "users": [usr]}]},
                               "streamSettings": ss}]}
        fd, p = tempfile.mkstemp(suffix=".json")
        os.write(fd, json.dumps(conf).encode()); os.close(fd)
        pr = subprocess.Popen([XRAY, "run", "-c", p],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5)
        r = subprocess.run(["curl", "-s", "-m", "8", "--socks5-hostname", f"127.0.0.1:{12900+i}",
                            "http://ip-api.com/json/?fields=status,country,query"],
                           capture_output=True, text=True)
        pr.terminate()
        try: os.unlink(p)
        except Exception: pass
        out = (r.stdout or "").strip()
        ok = '"status":"success"' in out
        info = ""
        try:
            dd = json.loads(out); info = f'{dd.get("query")} {dd.get("country")}'
        except Exception: pass
        print(f"    {'OK ' if ok else 'FAIL'} {unquote(uri.split('#')[-1])[:34]:<36} {info}")
        return uri if ok else None
    alive = []
    with ThreadPoolExecutor(max_workers=6) as ex:
        for r in ex.map(lambda t: one(t[0], t[1]), list(enumerate(links))):
            if r: alive.append(r)
    return alive

if __name__ == "__main__":
    sys.exit(main())
