#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
飞梭加速器（FaysoVPN）节点订阅生成器
====================================

协议逆向自 com.hyperlinksoftware.faysovpn_cn v1.0.8：
  POST /api/devices/register   {"deviceIdentifier","deviceName"} -> {"token"}
  POST /api/auth/login         {"username","password","deviceIdentifier","deviceName"} -> {"token"}
  GET  /api/connection/nodes   免鉴权
  GET  /api/connection/config?nodeId=<id>   Authorization: Bearer <token> -> sing-box 完整配置

产物（当前目录）：
  fayso_sub.txt        纯 hysteria2:// 订阅链接（通用客户端 / BetterBox 链接订阅）
  fayso_sub_b64.txt    base64 订阅（v2rayN / NekoBox 等标准订阅格式）
  fayso_clash.yaml     Mihomo / Clash.Meta 配置
  fayso_singbox.json   sing-box 完整配置（BetterBox / sing-box 官方客户端订阅）
  fayso_nodes.json     节点元数据（含延迟）

环境变量：
  FAYSO_TOKEN      已有 JWT，直接使用
  FAYSO_USERNAME   账号登录
  FAYSO_PASSWORD
  FAYSO_DEVICE_ID  固定设备标识（不填则随机生成并缓存在 .fayso_session.json）

仅用标准库，无需 pip 安装。
"""

import json
import os
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import base64
import concurrent.futures as futures

BASE = "https://api.hyperlink.us.com"
UA = "okhttp/4.12.0"
SESSION = ".fayso_session.json"

NON_PROXY = {"direct", "block", "dns", "selector", "urltest"}


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #
def http(method, path, token=None, body=None, timeout=25):
    headers = {"Accept-Language": "zh", "User-Agent": UA}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, str(e)


def jload(t):
    try:
        return json.loads(t)
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# 会话
# --------------------------------------------------------------------------- #
def load_session():
    if os.path.exists(SESSION):
        try:
            with open(SESSION) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_session(d):
    with open(SESSION, "w") as f:
        json.dump(d, f, ensure_ascii=False, indent=2)


def device_id(sess):
    di = os.environ.get("FAYSO_DEVICE_ID") or sess.get("deviceIdentifier")
    if not di:
        di = str(uuid.uuid4())
        sess["deviceIdentifier"] = di
        save_session(sess)
    return di


def register_device(sess):
    body = {"deviceIdentifier": device_id(sess), "deviceName": "Pixel 7"}
    code, text = http("POST", "/api/devices/register", body=body)
    d = jload(text) or {}
    if code in (200, 201) and d.get("token"):
        sess["token"] = d["token"]
        dev = d.get("device") or {}
        print(f"[+] 设备注册成功 {dev.get('id')} 试用剩余 {dev.get('trialSecondsRemaining')}s")
        return d["token"]
    print(f"[!] 设备注册失败 HTTP {code}: {text[:160]}")
    return None


def login(sess, username, password):
    body = {
        "username": username,
        "password": password,
        "deviceIdentifier": device_id(sess),
        "deviceName": "Pixel 7",
    }
    code, text = http("POST", "/api/auth/login", body=body)
    d = jload(text) or {}
    if code == 200 and d.get("token"):
        sess["token"] = d["token"]
        print(f"[+] 账号登录成功 {username}")
        return d["token"]
    print(f"[!] 登录失败 HTTP {code}: {(d.get('error') or text)[:160]}")
    return None


def get_token(sess):
    tok = os.environ.get("FAYSO_TOKEN")
    if tok:
        print("[*] 使用环境变量 FAYSO_TOKEN")
        return tok
    u, p = os.environ.get("FAYSO_USERNAME"), os.environ.get("FAYSO_PASSWORD")
    if u and p:
        return login(sess, u, p)
    if sess.get("token"):
        print("[*] 复用已缓存令牌")
        return sess["token"]
    return register_device(sess)


# --------------------------------------------------------------------------- #
# 业务
# --------------------------------------------------------------------------- #
def fetch_nodes():
    code, text = http("GET", "/api/connection/nodes")
    d = jload(text) or {}
    if code != 200:
        print(f"[!] 节点列表失败 HTTP {code}")
        return []
    return d.get("nodes", [])


def fetch_config(token, node_id, retries=3):
    path = "/api/connection/config?nodeId=" + urllib.parse.quote(node_id, safe="")
    code, text = 0, ""
    for i in range(retries):
        code, text = http("GET", path, token=token)
        if code == 200:
            return jload(text)
        if code == 401:
            break
        time.sleep(1.2 * (i + 1))
    return {"__error__": f"HTTP {code}: {text[:120]}"}


def pick_proxy(cfg):
    for ob in cfg.get("outbounds") or []:
        if ob.get("type") not in NON_PROXY:
            return ob
    return None


def probe(host, port, timeout=3.0):
    if not host or not port:
        return None
    t0 = time.time()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return int((time.time() - t0) * 1000)
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# 格式化
# --------------------------------------------------------------------------- #
def q(s):
    return urllib.parse.quote(str(s), safe="")


def to_link(ob, name):
    t = ob.get("type")
    server, port = ob.get("server"), ob.get("server_port")
    tls = ob.get("tls") or {}
    sni = tls.get("server_name") or ""
    extra = ""
    if sni:
        extra += "&sni=" + q(sni)
    if tls.get("insecure"):
        extra += "&insecure=1"

    if t == "hysteria2":
        obfs = ob.get("obfs") or {}
        if obfs.get("type") == "salamander":
            extra += "&obfs=salamander&obfs-password=" + q(obfs.get("password", ""))
        return f"hysteria2://{q(ob.get('password',''))}@{server}:{port}/?{extra.lstrip('&')}#{q(name)}"
    if t == "trojan":
        return f"trojan://{q(ob.get('password',''))}@{server}:{port}?{extra.lstrip('&')}#{q(name)}"
    if t == "shadowsocks":
        return f"ss://{q(ob.get('method','')+':'+ob.get('password',''))}@{server}:{port}#{q(name)}"
    if t == "vless":
        sec = "tls" if tls.get("enabled") else "none"
        return f"vless://{ob.get('uuid','')}@{server}:{port}?encryption=none&security={sec}{extra}#{q(name)}"
    return json.dumps(ob, ensure_ascii=False)


def yq(s):
    """YAML 单引号安全字符串"""
    return "'" + str(s).replace("'", "''") + "'"


def to_clash_proxy(ob, name):
    t = ob.get("type")
    tls = ob.get("tls") or {}
    lines = [f"  - name: {yq(name)}"]
    if t == "hysteria2":
        lines += [
            "    type: hysteria2",
            f"    server: {yq(ob.get('server'))}",
            f"    port: {ob.get('server_port')}",
            f"    password: {yq(ob.get('password',''))}",
        ]
        if tls.get("server_name"):
            lines.append(f"    sni: {yq(tls['server_name'])}")
        lines.append(f"    skip-cert-verify: {'true' if tls.get('insecure') else 'false'}")
        obfs = ob.get("obfs") or {}
        if obfs.get("type") == "salamander":
            lines.append("    obfs: salamander")
            lines.append(f"    obfs-password: {yq(obfs.get('password',''))}")
        lines += ["    up: '0'", "    down: '0'"]
    elif t == "trojan":
        lines += [
            "    type: trojan",
            f"    server: {yq(ob.get('server'))}",
            f"    port: {ob.get('server_port')}",
            f"    password: {yq(ob.get('password',''))}",
            f"    sni: {yq(tls.get('server_name',''))}",
            f"    skip-cert-verify: {'true' if tls.get('insecure') else 'false'}",
        ]
    elif t == "shadowsocks":
        lines += [
            "    type: ss",
            f"    server: {yq(ob.get('server'))}",
            f"    port: {ob.get('server_port')}",
            f"    cipher: {yq(ob.get('method',''))}",
            f"    password: {yq(ob.get('password',''))}",
        ]
    elif t == "vless":
        lines += [
            "    type: vless",
            f"    server: {yq(ob.get('server'))}",
            f"    port: {ob.get('server_port')}",
            f"    uuid: {yq(ob.get('uuid',''))}",
            "    network: tcp",
            f"    tls: {'true' if tls.get('enabled') else 'false'}",
        ]
        if tls.get("server_name"):
            lines.append(f"    servername: {yq(tls['server_name'])}")
    else:
        return None
    return "\n".join(lines)


def build_clash(named, nodes_by_tag):
    names = [n for n, _ in named]
    out = [
        "# 飞梭加速器（FaysoVPN）订阅 - 由 fayso.py 自动生成",
        "mixed-port: 7890",
        "allow-lan: false",
        "mode: rule",
        "log-level: info",
        "external-controller: 127.0.0.1:9090",
        "",
        "dns:",
        "  enable: true",
        "  ipv6: false",
        "  enhanced-mode: fake-ip",
        "  fake-ip-range: 198.18.0.1/16",
        "  nameserver:",
        "    - 223.5.5.5",
        "    - 119.29.29.29",
        "  fallback:",
        "    - https://1.1.1.1/dns-query",
        "    - https://8.8.8.8/dns-query",
        "",
        "proxies:",
    ]
    for name, ob in named:
        block = to_clash_proxy(ob, name)
        if block:
            out.append(block)
    out += ["", "proxy-groups:", "  - name: 节点选择", "    type: select",
            "    proxies:", "      - 自动选择"] + [f"      - {yq(n)}" for n in names]
    out += ["  - name: 自动选择", "    type: url-test",
            "    url: http://www.gstatic.com/generate_204",
            "    interval: 300", "    tolerance: 50", "    proxies:"]
    out += [f"      - {yq(n)}" for n in names]
    out += [
        "",
        "rules:",
        "  - DOMAIN-SUFFIX,cn,DIRECT",
        "  - GEOIP,CN,DIRECT",
        "  - MATCH,节点选择",
        "",
    ]
    return "\n".join(out)


def build_singbox(named):
    tags = [f"fayso-{i+1}" for i in range(len(named))]
    proxies = []
    for tag, (name, ob) in zip(tags, named):
        p = dict(ob)
        p["tag"] = tag
        p["_name"] = name
        proxies.append(p)
    clean = []
    for p in proxies:
        p = dict(p)
        p.pop("_name", None)
        clean.append(p)
    cfg = {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "remote", "type": "https", "server": "1.1.1.1",
                 "server_port": 443, "path": "/dns-query", "detour": "proxy"},
                {"tag": "local", "type": "local"},
            ],
            "rules": [{"ip_is_private": True, "server": "local"}],
            "final": "remote",
            "strategy": "ipv4_only",
        },
        "inbounds": [
            {"type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30"],
             "mtu": 9000, "auto_route": True, "strict_route": True, "stack": "mixed"},
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1",
             "listen_port": 7890},
        ],
        "outbounds": clean + [
            {"type": "selector", "tag": "proxy", "outbounds": tags + ["direct"],
             "default": tags[0] if tags else "direct"},
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
        ],
        "route": {
            "auto_detect_interface": True,
            "rules": [
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"ip_is_private": True, "outbound": "direct"},
            ],
            "final": "proxy",
        },
    }
    return cfg


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #
def main():
    sess = load_session()
    token = get_token(sess)
    if not token:
        print("[x] 无法获取令牌")
        return 1
    save_session(sess)

    nodes = fetch_nodes()
    if not nodes:
        print("[x] 节点列表为空")
        return 1

    real = [n for n in nodes if n.get("category") != "comingSoon" and n.get("probeHost")]
    print(f"[*] 节点 {len(nodes)} 个，可提取 {len(real)} 个")

    def collect(tk):
        """返回 (成功列表, 是否遇到 401)"""
        def work(n):
            return n, fetch_config(tk, n.get("value"), retries=3)

        ok, denied = [], False
        with futures.ThreadPoolExecutor(max_workers=5) as ex:
            for n, cfg in ex.map(work, real):
                if not cfg:
                    continue
                err = cfg.get("__error__") or ""
                if "401" in err:
                    denied = True
                if err:
                    print(f"    - {n.get('label')} 跳过 ({err})")
                    continue
                ob = pick_proxy(cfg)
                if not ob:
                    print(f"    - {n.get('label')} 无代理 outbound")
                    continue
                ok.append((n, ob))
                print(f"    + {n.get('label')} {ob.get('type')} "
                      f"{ob.get('server')}:{ob.get('server_port')}")
        return ok, denied

    ok, denied = collect(token)

    # 缓存令牌过期（JWT 有效期 30 天）时自动换一个新设备
    if not ok and denied and not os.environ.get("FAYSO_TOKEN"):
        print("[*] 令牌已失效，重新注册设备")
        token = register_device(sess)
        if token:
            save_session(sess)
            ok, _ = collect(token)

    if not ok:
        print("[x] 没拿到任何节点配置")
        return 1

    named = []
    meta = []
    for n, ob in ok:
        name = f"{n.get('flag','')}{n.get('label')}"
        named.append((name, ob))
        meta.append({
            "name": name,
            "value": n.get("value"),
            "protocol": ob.get("type"),
            "server": ob.get("server"),
            "port": ob.get("server_port"),
            "sni": (ob.get("tls") or {}).get("server_name"),
            "capacity": n.get("capacity"),
            "probe": [n.get("probeHost"), n.get("probePort")],
        })

    # 1) 纯链接
    links = [to_link(ob, name) for name, ob in named]
    with open("fayso_sub.txt", "w") as f:
        f.write("\n".join(links) + "\n")

    # 2) base64（v2ray 系标准订阅）
    with open("fayso_sub_b64.txt", "w") as f:
        f.write(base64.b64encode("\n".join(links).encode()).decode() + "\n")

    # 3) Clash / Mihomo
    with open("fayso_clash.yaml", "w") as f:
        f.write(build_clash(named, meta) + "\n")

    # 4) sing-box（BetterBox 订阅）
    with open("fayso_singbox.json", "w") as f:
        json.dump(build_singbox(named), f, ensure_ascii=False, indent=2)

    # 5) 元数据
    with open("fayso_nodes.json", "w") as f:
        json.dump({
            "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "count": len(meta),
            "nodes": meta,
        }, f, ensure_ascii=False, indent=2)

    print(f"[√] 生成 {len(named)} 个节点：fayso_sub.txt / fayso_sub_b64.txt / "
          f"fayso_clash.yaml / fayso_singbox.json / fayso_nodes.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
