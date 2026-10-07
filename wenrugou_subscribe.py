# -*- coding: utf-8 -*-
"""
WenruGou nodes -> 只生成两个文件：wenrugou.txt + clash_config.yaml

本版相对原脚本的改动：
  1. 注释全部恢复为正常 UTF-8 中文（原文件被 GBK/UTF-8 反复转码，已损坏不可逆）
  2. SS 插件归一化：obfs-local -> obfs、obfs -> mode、obfs-host -> host（Clash/Mihomo 标准）
  3. plugin_opts 支持无值开关（如 tls、mux），不再被 "=" 判断吃掉
  4. 健康探测按协议分流：SS/SSR 只做 TCP 连通，不再发 TLS ClientHello（避免误杀/假阳性）

注意：本文件必须以 UTF-8 编码保存，不要用 GBK 另存，否则注释会再次变成乱码。
"""
import os
import sys
import json
import time
import socket
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

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
REMOTE_SB_SUB_URL = "https://cdn.jsdelivr.net/gh/Luckdog-cook/lanmao-sub@main/wenrugou&nk.txt"

# 非 TLS 协议：不做 ClientHello 探测，只测 TCP 连通
NO_TLS_PROTO = ("shadowsocks", "ss", "shadowsocksr", "ssr", "hysteria", "hy", "hysteria2", "hy2")


# ============================================================ 通用字段提取
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


# ============================================================ SS 插件归一化
# SIP003 / shadowsocks-libev 的插件名 -> Clash / Mihomo 认识的 plugin 名
SS_PLUGIN_ALIAS = {
    "obfs-local": "obfs",
    "obfs-server": "obfs",
    "simple-obfs": "obfs",
    "obfs": "obfs",
    "v2ray-plugin": "v2ray-plugin",
    "gost-plugin": "gost-plugin",
    "shadow-tls": "shadow-tls",
    "restls": "restls",
    "kcptun": "kcptun",
    "jls": "jls",
}


def _parse_plugin_opts(raw):
    """解析 SIP003 串：obfs=http;obfs-host=a.com;tls

    无 '=' 的独立开关（tls / mux 等）保留为 True，不能被丢掉。
    """
    if isinstance(raw, dict):
        return {str(k): v for k, v in raw.items()}
    opts = {}
    for kv in (raw or "").split(";"):
        kv = kv.strip()
        if not kv:
            continue
        if "=" in kv:
            k, v = kv.split("=", 1)
            opts[k.strip()] = v.strip()
        else:
            opts[kv] = True
    return opts


def _first(d, *keys, default=None):
    for k in keys:
        v = d.get(k)
        if v not in (None, "", True):
            return v
    return default


def normalize_ss_plugin(plugin_name, plugin_opts):
    """(SIP003 插件名, opts串) -> (clash plugin, clash plugin-opts)；无法识别返回 (None, {})"""
    key = (plugin_name or "").strip().lower()
    opts = _parse_plugin_opts(plugin_opts)

    # 兜底：plugin 字段缺失但 opts 带 obfs= / mode= 等，反推插件类型
    if not key:
        if "obfs" in opts or "obfs-host" in opts:
            key = "obfs-local"
        elif "mode" in opts or "path" in opts:
            key = "v2ray-plugin"
        else:
            return None, {}

    clash = SS_PLUGIN_ALIAS.get(key)
    if not clash:
        return None, {}

    if clash == "obfs":
        out = {"mode": str(_first(opts, "obfs", "mode", default="http")).lower()}
        host = _first(opts, "obfs-host", "host", "obfs_host")
        if host:
            out["host"] = host
        return clash, out

    if clash == "v2ray-plugin":
        mode = str(_first(opts, "mode", default="websocket")).lower()
        out = {"mode": "quic" if mode == "quic" else "websocket"}
        if opts.get("tls") is True or str(opts.get("tls")).lower() == "true":
            out["tls"] = True
        if opts.get("mux") is True:
            out["mux"] = True
        for k in ("host", "path", "fingerprint", "skip-cert-verify", "v2ray-http-upgrade"):
            if k in opts and opts[k] is not True:
                out[k] = opts[k]
        return clash, out

    # shadow-tls / restls / kcptun / jls / gost-plugin：键名本来就是 clash 风格，原样保留
    return clash, {k: v for k, v in opts.items()}


def apply_ss_plugin(p, cfg):
    """把插件信息写进 ss 节点字典 p（原地修改）"""
    raw_plugin = cfg.get("plugin") or cfg.get("plugin_name") or ""
    raw_opts = cfg.get("plugin_opts") or cfg.get("plugin_options") or ""

    plugin, opts = normalize_ss_plugin(raw_plugin, raw_opts)
    if plugin:
        p["plugin"] = plugin
        if opts:
            p["plugin-opts"] = opts
        return p

    if raw_plugin:
        # 未知插件：别静默丢弃，原样透传 + 提示，方便排查
        p["plugin"] = raw_plugin
        o = _parse_plugin_opts(raw_opts)
        if o:
            p["plugin-opts"] = o
        print("WARN: 未识别的 SS 插件 %r，已原样透传" % raw_plugin)
    elif raw_opts:
        print("WARN: 有 plugin_opts 但没有 plugin，已丢弃: %r" % raw_opts)
    return p


# ============================================================ sing-box 输出（NekoBox / sing-box 内核）
# 关键差异：sing-box 的 ss 插件只认 SIP003 原生写法
#     plugin: obfs-local                （Clash/Mihomo 要的是 obfs）
#     plugin_opts: "obfs=http;obfs-host=xxx"  （Clash/Mihomo 要的是 {mode, host}）
# 两者互不兼容，所以必须单独出一份订阅，不能复用 wenrugou.txt
SB_PLUGIN_ALIAS = {
    "obfs": "obfs-local",
    "obfs-local": "obfs-local",
    "obfs-server": "obfs-local",
    "simple-obfs": "obfs-local",
    "v2ray-plugin": "v2ray-plugin",
}


def _sip003_str(raw):
    """plugin_opts 统一成 SIP003 字符串：obfs=http;obfs-host=a.com;tls"""
    if isinstance(raw, dict):
        parts = []
        for k, v in raw.items():
            parts.append(k if v is True else "%s=%s" % (k, v))
        return ";".join(parts)
    return raw or ""


def _sb_tls(tls):
    """API 的 tls 对象 -> sing-box 的 tls 对象"""
    if not tls or not tls.get("enabled"):
        return None
    out = {"enabled": True}
    if tls.get("server_name"):
        out["server_name"] = tls["server_name"]
    if tls.get("insecure"):
        out["insecure"] = True
    alpn = tls.get("alpn")
    if alpn:
        out["alpn"] = alpn if isinstance(alpn, list) else [alpn]
    utls = tls.get("utls") or {}
    if utls.get("enabled") and utls.get("fingerprint"):
        out["utls"] = {"enabled": True, "fingerprint": utls["fingerprint"]}
    r = tls.get("reality") or {}
    if r.get("enabled"):
        out["reality"] = {
            "enabled": True,
            "public_key": r.get("public_key", ""),
            "short_id": r.get("short_id", ""),
        }
    return out


def _sb_transport(tr):
    """API 的 transport 对象 -> sing-box 的 transport 对象"""
    if not tr:
        return None
    net = (tr.get("type") or "tcp").strip()
    if net in ("tcp", "", "raw"):
        return None
    out = {"type": net}
    if net in ("ws", "httpupgrade"):
        out["path"] = tr.get("path") or "/"
        headers = tr.get("headers") or {}
        host = headers.get("Host") or headers.get("host")
        if host:
            out["headers"] = {"Host": host}
    elif net == "grpc":
        out["service_name"] = tr.get("service_name", "") or ""
    elif net in ("http", "h2"):
        out["path"] = tr.get("path") or "/"
        host = tr.get("host")
        if isinstance(host, list):
            out["host"] = host
        elif host:
            out["host"] = [host]
    return out


def to_singbox_outbound(node):
    """API 节点 -> sing-box outbound；不支持的协议返回 None"""
    cfg = node.get("config", {}) or {}
    proto = (node.get("protocol") or "").lower().strip()
    tls = cfg.get("tls", {}) or {}
    tr = cfg.get("transport", {}) or {}
    server = cfg.get("server", "")
    try:
        port = int(cfg.get("server_port", 0) or 0)
    except Exception:
        port = 0
    if not server or not port:
        return None

    o = {"tag": node.get("name", "node"), "server": server, "server_port": port}

    if proto in ("shadowsocks", "ss"):
        o.update({"type": "shadowsocks",
                  "method": cfg.get("method", "aes-256-gcm") or "aes-256-gcm",
                  "password": str(cfg.get("password", ""))})
        raw_plugin = (cfg.get("plugin") or "").strip().lower()
        sb_plugin = SB_PLUGIN_ALIAS.get(raw_plugin)
        if sb_plugin:
            o["plugin"] = sb_plugin
            opts = _sip003_str(cfg.get("plugin_opts") or cfg.get("plugin_options") or "")
            if opts:
                o["plugin_opts"] = opts
        elif raw_plugin:
            print("WARN: sing-box 不支持的 SS 插件 %r，已忽略（仅支持 obfs-local / v2ray-plugin）" % raw_plugin)
    elif proto == "trojan":
        o.update({"type": "trojan", "password": str(cfg.get("password", ""))})
    elif proto == "vless":
        o.update({"type": "vless", "uuid": cfg.get("uuid", "")})
        if cfg.get("flow"):
            o["flow"] = cfg["flow"]
    elif proto == "vmess":
        o.update({"type": "vmess", "uuid": cfg.get("uuid", ""),
                  "alter_id": int(cfg.get("alter_id", 0) or 0),
                  "security": cfg.get("security", "auto") or "auto"})
    elif proto in ("hysteria2", "hy2"):
        o.update({"type": "hysteria2", "password": str(cfg.get("password", cfg.get("auth", "")))})
        if cfg.get("up_mbps"):
            o["up_mbps"] = int(cfg["up_mbps"])
        if cfg.get("down_mbps"):
            o["down_mbps"] = int(cfg["down_mbps"])
        obfs = cfg.get("obfs")
        if isinstance(obfs, dict) and obfs.get("type"):
            o["obfs"] = {"type": obfs["type"]}
            if obfs.get("password"):
                o["obfs"]["password"] = obfs["password"]
    elif proto in ("hysteria", "hy"):
        o.update({"type": "hysteria",
                  "auth_str": str(cfg.get("auth_str", cfg.get("auth", cfg.get("password", ""))))})
        if cfg.get("up_mbps"):
            o["up_mbps"] = int(cfg["up_mbps"])
        if cfg.get("down_mbps"):
            o["down_mbps"] = int(cfg["down_mbps"])
    elif proto == "anytls":
        o.update({"type": "anytls", "password": str(cfg.get("password", ""))})
    else:
        return None

    t = _sb_tls(tls)
    if t:
        o["tls"] = t
    tp = _sb_transport(tr)
    if tp:
        o["transport"] = tp
    return o


def write_singbox_config(nodes, path):
    """生成 NekoBox / sing-box 可直接订阅的完整 JSON 配置"""
    outs, seen = [], set()
    for n in nodes:
        o = to_singbox_outbound(n)
        if not o:
            continue
        tag, i = o["tag"], 1
        while tag in seen:
            i += 1
            tag = "%s #%d" % (o["tag"], i)
        o["tag"] = tag
        seen.add(tag)
        outs.append(o)
    if not outs:
        return 0

    tags = [o["tag"] for o in outs]
    cfg = {
        "log": {"level": "info"},
        # 不写 dns 段：新旧版 sing-box 的 dns.server 字段名不兼容，
        # 留空交给 NekoBox 用内置默认 DNS，最稳
        "outbounds": [
            {"type": "selector", "tag": "PROXY", "outbounds": ["AUTO"] + tags + ["DIRECT"]},
            {"type": "urltest", "tag": "AUTO", "outbounds": tags,
             "url": "http://www.gstatic.com/generate_204",
             "interval": "3m", "tolerance": 50},
        ] + outs + [
            {"type": "direct", "tag": "DIRECT"},
        ],
        "route": {
            "rules": [
                {"domain_suffix": [".cn"], "outbound": "DIRECT"},
            ],
            "final": "PROXY",
            "auto_detect_interface": True,
        },
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    return len(outs)


# ============================================================ 节点转换
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
        _tls_common(tls, p)
        p.update(_network_opts(tr, net))
    elif proto == "trojan":
        p.update({"type": "trojan", "password": cfg.get("password", ""), "network": net, "udp": True})
        _tls_common(tls, p)
        p.update(_network_opts(tr, net))
    elif proto == "vmess":
        p.update({"type": "vmess", "uuid": cfg.get("uuid", ""),
                  "alterId": int(cfg.get("alter_id", 0) or 0),
                  "cipher": cfg.get("security", "auto") or "auto",
                  "network": net, "udp": True})
        _tls_common(tls, p)
        p.update(_network_opts(tr, net))
    elif proto in ("shadowsocks", "ss"):
        p.update({"type": "ss", "cipher": cfg.get("method", "aes-256-gcm"),
                  "password": str(cfg.get("password", "")), "udp": True})
        apply_ss_plugin(p, cfg)
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


# ============================================================ 输出文件
def write_wenrugou_txt(nodes, path):
    """生成供 proxy-provider 拉取的订阅内容（纯 proxies 列表）"""
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


# ============================================================ 健康探测
def build_client_hello(sni):
    """手工构造一个最小 TLS ClientHello，仅用于探测服务端是否有 TLS 层响应"""
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
    """探测服务端是否响应 TLS。

    Reality 服务端收到非 Reality 的 ClientHello 时通常会转发到 dest 并返回证书，
    因此"收到任何字节"即可认为该端口存活；完全 0 字节响应或 RST 说明端口已失效。
    """
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except Exception as e:
        return False, "TCP失败: %s" % type(e).__name__
    try:
        s.settimeout(timeout)
        s.sendall(build_client_hello(sni or host))
        data = s.recv(2048)
        if data:
            return True, "有响应(%dB)" % len(data)
        return False, "无响应(0字节)"
    except socket.timeout:
        return False, "TLS握手无响应(超时)"
    except Exception as e:
        return False, "%s: %s" % (type(e).__name__, str(e)[:40])
    finally:
        try:
            s.close()
        except Exception:
            pass


def tcp_alive(host, port, timeout=6):
    """非 TLS 协议（SS/SSR/Hysteria）只测 TCP 连通，不做 TLS 握手。

    实测：SS + obfs 端口对 ClientHello 会回一个 HTTP/1.1 400，
    用 TLS 探测判活属于假阳性；反过来遇到静默端口又会被误杀。
    """
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except Exception as e:
        return False, "TCP失败: %s" % type(e).__name__
    try:
        s.close()
        return True, "TCP可连接"
    except Exception:
        return True, "TCP可连接"


def health_check(nodes, workers=16):
    """并发探测节点存活，返回 (存活节点列表, 探测报告)"""
    def work(n):
        cfg = n.get("config", {}) or {}
        proto = (n.get("protocol") or "").lower().strip()
        host = cfg.get("server", "")
        try:
            port = int(cfg.get("server_port", 0) or 0)
        except Exception:
            port = 0
        sni = (cfg.get("tls", {}) or {}).get("server_name") or ""
        if not host or not port:
            return n, False, "缺少地址/端口"
        if proto in NO_TLS_PROTO:
            ok, reason = tcp_alive(host, port)
        else:
            ok, reason = tls_alive(host, port, sni)
        return n, ok, reason

    alive, report = [], []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for n, ok, reason in ex.map(work, nodes):
            report.append((n.get("name", "?"), ok, reason))
            if ok:
                alive.append(n)
    return alive, report


# ============================================================ 主流程
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

    # 发布前健康探测：剔除端口已失效的节点，避免推送一堆必然超时的死链
    # 云端(GitHub Actions / GitLab CI 等)对这些国内节点基本不可达，跳过；
    # 本地 Termux 正常探测。设置 WENRG_SKIP_HEALTH=1 可强制跳过。
    skip_health = (
        os.environ.get("WENRG_SKIP_HEALTH", "").lower() in ("1", "true", "yes")
        or os.environ.get("GITHUB_ACTIONS", "").lower() == "true"
        or os.environ.get("CI", "").lower() == "true"
    )
    if skip_health:
        print("[health] skipped (CI environment, trust API data)")
    else:
        print("[health] probing nodes...")
        nodes, report = health_check(nodes)
        for name, ok, reason in report:
            print(f"  [{'OK  ' if ok else 'DEAD'}] {name} - {reason}")
        if not nodes:
            print("WARN: 全部节点未通过健康探测 -> 不覆盖旧订阅，保留上一次可用版本")
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

    # NekoBox / sing-box 用这份：ss 插件保留 SIP003 原生写法（obfs-local + obfs=http;obfs-host=...）
    sb_path = os.path.join(SAVE_DIR, "wenrugou&nk.txt")
    m = write_singbox_config(nodes, sb_path)
    print(f"OK: {sb_path}  ({m} outbounds)")

    print(f"remote sub (clash):   {REMOTE_CLASH_SUB_URL}")
    print(f"remote sub (singbox): {REMOTE_SB_SUB_URL}")
    print("done")


if __name__ == "__main__":
    main()
