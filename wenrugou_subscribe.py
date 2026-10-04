# -*- coding: utf-8 -*-
"""WenruGou nodes -> generate only 2 files: wenrugou.txt + clash_config.yaml"""
import os, sys, json, time, base64, urllib.parse, socket, requests
from datetime import datetime
import yaml

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

API_URL = os.environ.get("WENR_GOU_API", "https://www.wenrugou.net/api/nodes")
HEADERS = {
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 16; 25053RT47C Build/BP2A.250605.031.A3)",
    "Host": "www.wenrugou.net",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip, deflate",
    "Accept": "application/json",
}
DEFAULT_DIR = "/storage/emulated/0/Download/wenrugou"
SAVE_DIR = DEFAULT_DIR if os.path.exists("/storage/emulated/0") else os.path.join(os.getcwd(), "download", "wenrugou")

REMOTE_CLASH_SUB_URL = "https://cdn.jsdelivr.net/gh/Luckdog-cook/lanmao-sub@main/wenrugou.txt"


def _headers_host(t):
    h = t.get("headers", {}) or {}
    return h.get("Host") or h.get("host") or ""


def _network_opts(t, net):
    opts = {}
    path = t.get("path", "") or "/"
    host = _headers_host(t)
    if net in ("ws", "httpupgrade", "splithttp", "xhttp"):
        ws = {"path": path}
        if host:
            ws["headers"] = {"Host": host}
        opts["ws-opts"] = ws
    elif net == "grpc":
        opts["grpc-opts"] = {"grpc-service-name": t.get("service_name", "") or ""}
    elif net in ("http", "h2"):
        hosts = t.get("host", "")
        h2 = {"path": path}
        if isinstance(hosts, list):
            h2["host"] = hosts
        elif hosts:
            h2["host"] = [hosts]
        elif host:
            h2["host"] = [host]
        opts["h2-opts"] = h2
    return opts


def _tls_common(tls, out):
    if not tls.get("enabled"):
        return
    out["tls"] = True
    if tls.get("server_name"):
        out["servername"] = tls["server_name"]
    fp = (tls.get("utls") or {}).get("fingerprint")
    if fp:
        out["client-fingerprint"] = fp
    if tls.get("insecure"):
        out["skip-cert-verify"] = True
    alpn = tls.get("alpn")
    if alpn:
        out["alpn"] = alpn if isinstance(alpn, list) else [alpn]
    r = tls.get("reality") or {}
    if r.get("enabled"):
        out["reality-opts"] = {
            "public-key": r.get("public_key", ""),
            "short-id": r.get("short_id", ""),
        }


def to_clash_proxy(node):
    cfg = node.get("config", {}) or {}
    proto = (node.get("protocol") or "").lower().strip()
    tls = cfg.get("tls", {}) or {}
    tr = cfg.get("transport", {}) or {}
    net = tr.get("type", "tcp") or "tcp"
    p = {"name": node.get("name", "node"), "server": cfg.get("server", ""),
         "port": int(cfg.get("server_port", 0) or 0)}

    if proto == "vless":
        p.update({"type": "vless", "uuid": cfg.get("uuid", ""), "network": net, "udp": True})
        if cfg.get("flow"):
            p["flow"] = cfg["flow"]
        _tls_common(tls, p); p.update(_network_opts(tr, net))
    elif proto == "trojan":
        p.update({"type": "trojan", "password": cfg.get("password", ""), "network": net, "udp": True})
        _tls_common(tls, p); p.update(_network_opts(tr, net))
    elif proto == "vmess":
        p.update({"type": "vmess", "uuid": cfg.get("uuid", ""),
                  "alterId": int(cfg.get("alter_id", 0) or 0),
                  "cipher": cfg.get("security", "auto") or "auto",
                  "network": net, "udp": True})
        _tls_common(tls, p); p.update(_network_opts(tr, net))
    elif proto in ("shadowsocks", "ss"):
        p.update({"type": "ss", "cipher": cfg.get("method", "aes-256-gcm"),
                  "password": str(cfg.get("password", "")), "udp": True})
        if cfg.get("plugin"):
            p["plugin"] = cfg["plugin"]
            opts = {}
            for kv in (cfg.get("plugin_opts", "") or "").split(";"):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    opts[k.strip()] = v.strip()
            if opts:
                p["plugin-opts"] = opts
    elif proto in ("shadowsocksr", "ssr"):
        p.update({"type": "ssr", "cipher": cfg.get("method", "aes-256-cfb"),
                  "password": str(cfg.get("password", "")),
                  "protocol": cfg.get("protocol", "origin") or "origin",
                  "obfs": cfg.get("obfs", "plain") or "plain", "udp": True})
        if cfg.get("protocol_param"):
            p["protocol-param"] = cfg["protocol_param"]
        if cfg.get("obfs_param"):
            p["obfs-param"] = cfg["obfs_param"]
    elif proto in ("hysteria", "hy"):
        p["type"] = "hysteria"
        p["auth-str"] = cfg.get("auth_str", cfg.get("auth", cfg.get("password", "")))
        if cfg.get("up_mbps"):
            p["up"] = str(cfg["up_mbps"])
        if cfg.get("down_mbps"):
            p["down"] = str(cfg["down_mbps"])
        if tls.get("server_name"):
            p["sni"] = tls["server_name"]
        if tls.get("insecure"):
            p["skip-cert-verify"] = True
        if tls.get("alpn"):
            p["alpn"] = tls["alpn"] if isinstance(tls["alpn"], list) else [tls["alpn"]]
        if cfg.get("protocol"):
            p["protocol"] = cfg["protocol"]
        if cfg.get("obfs"):
            p["obfs"] = cfg["obfs"]
    elif proto in ("hysteria2", "hy2"):
        p["type"] = "hysteria2"
        p["password"] = str(cfg.get("password", cfg.get("auth", "")))
        if tls.get("server_name"):
            p["sni"] = tls["server_name"]
        if tls.get("insecure"):
            p["skip-cert-verify"] = True
        if tls.get("alpn"):
            p["alpn"] = tls["alpn"] if isinstance(tls["alpn"], list) else [tls["alpn"]]
        if cfg.get("ports"):
            p["ports"] = str(cfg["ports"])
        if cfg.get("hop_interval"):
            p["hop-interval"] = int(cfg["hop_interval"])
        obfs = cfg.get("obfs")
        if isinstance(obfs, dict) and obfs.get("type"):
            p["obfs"] = obfs["type"]
            if obfs.get("password"):
                p["obfs-password"] = obfs["password"]
    elif proto == "anytls":
        p["type"] = "anytls"
        p["password"] = str(cfg.get("password", ""))
        if tls.get("server_name"):
            p["sni"] = tls["server_name"]
        fp = (tls.get("utls") or {}).get("fingerprint")
        if fp:
            p["client-fingerprint"] = fp
        if tls.get("insecure"):
            p["skip-cert-verify"] = True
        p["udp"] = True
    else:
        return None
    return p


def write_wenrugou_txt(nodes, path):
    proxies, seen = [], set()
    for n in nodes:
        p = to_clash_proxy(n)
        if not p:
            continue
        name, i = p["name"], 1
        while name in seen:
            i += 1
            name = f"{p['name']} #{i}"
        p["name"] = name
        seen.add(name)
        proxies.append(p)
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump({"proxies": proxies}, f, allow_unicode=True,
                  sort_keys=False, default_flow_style=False)
    return len(proxies)


def write_clash_config(path):
    cfg = {
        "mixed-port": 7890,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "external-controller": "127.0.0.1:9090",
        "dns": {
            "enable": True,
            "ipv6": False,
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "default-nameserver": ["223.5.5.5", "8.8.8.8"],
            "nameserver": ["https://dns.alidns.com/dns-query", "https://doh.pub/dns-query"],
            "fallback": ["https://1.0.0.1/dns-query", "tls://dns.google"],
        },
        "proxy-providers": {
            "wenrugou": {
                "type": "http",
                "url": REMOTE_CLASH_SUB_URL,
                "path": "./providers/wenrugou.yaml",
                "interval": 3600,
                "health-check": {
                    "enable": True,
                    "url": "http://www.gstatic.com/generate_204",
                    "interval": 300,
                },
            }
        },
        "proxy-groups": [
            {"name": "PROXY", "type": "select",
             "proxies": ["AUTO", "FALLBACK", "DIRECT"]},
            {"name": "AUTO", "type": "url-test", "use": ["wenrugou"],
             "url": "http://www.gstatic.com/generate_204", "interval": 300, "tolerance": 50},
            {"name": "FALLBACK", "type": "fallback", "use": ["wenrugou"],
             "url": "http://www.gstatic.com/generate_204", "interval": 300},
        ],
        "rules": [
            "DOMAIN-SUFFIX,cn,DIRECT",
            "DOMAIN-KEYWORD,baidu,DIRECT",
            "DOMAIN-KEYWORD,taobao,DIRECT",
            "DOMAIN-KEYWORD,jd,DIRECT",
            "DOMAIN-KEYWORD,qq,DIRECT",
            "DOMAIN-KEYWORD,weixin,DIRECT",
            "DOMAIN-KEYWORD,alipay,DIRECT",
            "DOMAIN-KEYWORD,google,PROXY",
            "DOMAIN-KEYWORD,youtube,PROXY",
            "DOMAIN-KEYWORD,github,PROXY",
            "DOMAIN-KEYWORD,telegram,PROXY",
            "DOMAIN-KEYWORD,twitter,PROXY",
            "GEOIP,CN,DIRECT",
            "MATCH,PROXY",
        ],
    }
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(cfg, f, allow_unicode=True, sort_keys=False, default_flow_style=False)


def build_client_hello(sni):
    """鎵嬪伐鏋勯€犱竴涓渶灏� TLS ClientHello锛屼粎鐢ㄤ簬鎺㈡祴鏈嶅姟绔槸鍚︽湁 TLS 灞傚搷搴斻€�"""
    ext = b""
    if sni:
        name = sni.encode("utf-8")
        entry = b"\x00" + len(name).to_bytes(2, "big") + name
        data = len(entry).to_bytes(2, "big") + entry
        ext += b"\x00\x00" + len(data).to_bytes(2, "big") + data
    d = b"\x04\x03\x04"                      # supported_versions: TLS1.3
    ext += b"\x00\x2b" + len(d).to_bytes(2, "big") + d
    groups = b"\x00\x1d\x00\x17\x00\x18"     # supported_groups
    d = len(groups).to_bytes(2, "big") + groups
    ext += b"\x00\x0a" + len(d).to_bytes(2, "big") + d
    algs = bytes.fromhex("04030804040105030805050108060601")   # signature_algorithms
    d = len(algs).to_bytes(2, "big") + algs
    ext += b"\x00\x0d" + len(d).to_bytes(2, "big") + d
    ciphers = bytes.fromhex("130113021303c02fc02bc030")
    body = (b"\x03\x03" + os.urandom(32) + b"\x00"
            + len(ciphers).to_bytes(2, "big") + ciphers
            + b"\x01\x00" + len(ext).to_bytes(2, "big") + ext)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def tls_alive(host, port, sni, timeout=6):
    """鎺㈡祴鏈嶅姟绔槸鍚﹀搷搴� TLS銆�

    Reality 鏈嶅姟绔敹鍒伴潪 Reality 鐨� ClientHello 鏃堕€氬父浼氳浆鍙戝埌 dest 骞惰繑鍥炶瘉涔︼紝
    鍥犳"鏀跺埌浠讳綍瀛楄妭"鍗冲彲璁や负璇ョ鍙ｅ瓨娲伙紱瀹屽叏 0 瀛楄妭鍝嶅簲鎴� RST 璇存槑绔彛宸插け鏁堛€�
    """
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except Exception as e:
        return False, "TCP澶辫触: %s" % type(e).__name__
    try:
        s.settimeout(timeout)
        s.sendall(build_client_hello(sni or host))
        data = s.recv(2048)
        if data:
            return True, "鏈夊搷搴�(%dB)" % len(data)
        return False, "鏃犲搷搴�(0瀛楄妭)"
    except socket.timeout:
        return False, "TLS鎻℃墜鏃犲搷搴�(瓒呮椂)"
    except Exception as e:
        return False, "%s: %s" % (type(e).__name__, str(e)[:40])
    finally:
        try:
            s.close()
        except Exception:
            pass


def health_check(nodes, workers=16):
    """骞跺彂鎺㈡祴鑺傜偣瀛樻椿锛岃繑鍥� (瀛樻椿鑺傜偣鍒楄〃, 鎺㈡祴鎶ュ憡)銆�"""
    from concurrent.futures import ThreadPoolExecutor

    def work(n):
        cfg = n.get("config", {}) or {}
        host = cfg.get("server", "")
        try:
            port = int(cfg.get("server_port", 0) or 0)
        except Exception:
            port = 0
        sni = (cfg.get("tls", {}) or {}).get("server_name") or ""
        if not host or not port:
            return n, False, "缂哄皯鍦板潃/绔彛"
        ok, reason = tls_alive(host, port, sni)
        return n, ok, reason

    alive, report = [], []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for n, ok, reason in ex.map(work, nodes):
            report.append((n.get("name", "?"), ok, reason))
            if ok:
                alive.append(n)
    return alive, report


def fetch_api_with_retry(max_retries=3, retry_delay=2):
    for i in range(1, max_retries + 1):
        try:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] fetch nodes ({i}/{max_retries})...")
            r = requests.get(API_URL, headers=HEADERS, timeout=15)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            print(f"WARN: attempt {i} failed: {e}")
            if i < max_retries:
                time.sleep(retry_delay)
    print("ERROR: max retries reached")
    return None


def main():
    data = fetch_api_with_retry()
    if not data:
        return
    nodes = data.get("nodes", [])
    if not nodes:
        print("no nodes")
        return
    print(f"got {len(nodes)} nodes, generating...")

    # 鍙戝竷鍓嶅仴搴锋帰娴嬶細鍓旈櫎绔彛宸插け鏁堢殑鑺傜偣锛岄伩鍏嶆帹閫佷竴鍫嗗繀鐒惰秴鏃剁殑姝婚摼
    print("[health] probing nodes...")
    nodes, report = health_check(nodes)
    for name, ok, reason in report:
        print(f"  [{'OK  ' if ok else 'DEAD'}] {name} - {reason}")
    if not nodes:
        print("ERROR: 鍏ㄩ儴鑺傜偣鏈€氳繃鍋ュ悍鎺㈡祴 -> 涓嶈鐩栨棫璁㈤槄锛屼繚鐣欎笂涓€娆″彲鐢ㄧ増鏈�")
        return
    print(f"[health] alive {len(nodes)}/{len(report)}")

    os.makedirs(SAVE_DIR, exist_ok=True)
    print(f"DIR: {SAVE_DIR}")

    wenru_path = os.path.join(SAVE_DIR, "wenrugou.txt")
    n = write_wenrugou_txt(nodes, wenru_path)
    print(f"OK: {wenru_path}  ({n} proxies)")

    clash_path = os.path.join(SAVE_DIR, "clash_config.yaml")
    write_clash_config(clash_path)
    print(f"OK: {clash_path}")
    print(f"remote sub: {REMOTE_CLASH_SUB_URL}")
    print("done")


if __name__ == "__main__":
    main()
