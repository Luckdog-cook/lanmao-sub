#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
星链 VPN 自动抓取（增强版）
- 实时获取国内 + 国际节点
- 输出：纯订阅链接 / Clash Meta / sing-box
- 支持环境变量覆盖 Token / Device ID
"""

import base64
import json
import os
import ssl
import sys
import urllib.parse
import urllib.request
from typing import List, Optional, Dict, Any

# ==================== 配置（可用环境变量覆盖） ====================
API = "https://apis.nexgentechhub.net/api/v1/auth/get_configs"
TOKEN = os.getenv(
    "SINGLINK_TOKEN",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOiI4ODIxODg3MTEwNjI2NjcyNjQiLCJleHAiOjQzODAxMzkwNzgsInJvbGUiOjF9.Uq2mImzv8fSCuMbBatPFrMX4XaLGC-_K8eWRsuzfsrY",
)
DEVICE = os.getenv("SINGLINK_DEVICE", "9a6d8d2a-5f70-4f14-ad10-8fc94b879570")
KEY = b"mateforce-cn-jiasuqi-length-keys"

# 输出文件名（可被环境变量覆盖）
OUT_TXT = os.getenv("OUT_TXT", "safevpn_sub.txt")
OUT_CLASH = os.getenv("OUT_CLASH", "clash.yaml")
OUT_SINGBOX = os.getenv("OUT_SINGBOX", "sing-box.json")


# ==================== AES 解密 ====================
try:
    from Crypto.Cipher import AES

    def decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
        return AES.new(key, AES.MODE_CBC, iv).decrypt(data)

except ImportError:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    def decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return decryptor.update(data) + decryptor.finalize()


def unpad(b: bytes) -> bytes:
    p = b[-1]
    if not (1 <= p <= 16) or b[-p:] != bytes([p]) * p:
        raise ValueError("填充错误")
    return b[:-p]


# ==================== 输出目录 ====================
def get_output_dir() -> str:
    # 优先使用环境变量指定的目录（GitHub Actions 推荐设为 "."）
    if os.getenv("OUTPUT_DIR"):
        return os.getenv("OUTPUT_DIR")
    for d in [os.environ.get("EXTERNAL_STORAGE", ""), "/storage/emulated/0", "/sdcard"]:
        p = os.path.join(d, "Download")
        if os.path.exists(p) or os.access(os.path.dirname(p) or ".", os.W_OK):
            return p
    return "."


# ==================== 请求与解密 ====================
def fetch(is_cn: bool) -> dict:
    body = json.dumps(
        {"is_from_cn": is_cn, "platform": "android", "is_list_mode": False}
    ).encode()
    headers = {
        "User-Agent": "Dart/3.10",
        "Content-Type": "application/json",
        "x-device-id": DEVICE,
        "authorization": TOKEN,
    }
    req = urllib.request.Request(API, data=body, headers=headers, method="POST")
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=60, context=ctx) as r:
        res = json.loads(r.read())
    data = res.get("data", {})
    if "encrypted" not in data or "iv" not in data:
        raise ValueError(f"API 返回异常: {res}")
    ct = base64.b64decode(data["encrypted"])
    iv = base64.b64decode(data["iv"])
    plain = unpad(decrypt(KEY, iv, ct))
    return json.loads(plain.decode())


# ==================== 生成纯链接 ====================
def make_uri(n: dict, prefix: str) -> Optional[str]:
    typ = n.get("type")
    tag = f"{prefix}{n.get('tag', 'node')}"
    if typ == "vless":
        t = n.get("tls", {})
        r = t.get("reality", {})
        params = {
            "encryption": "none",
            "flow": n.get("flow", ""),
            "security": "reality",
            "sni": t.get("server_name", ""),
            "fp": t.get("utls", {}).get("fingerprint", "chrome"),
            "pbk": r.get("public_key", ""),
            "sid": r.get("short_id", ""),
            "type": "tcp",
            "headerType": "none",
        }
        q = urllib.parse.urlencode({k: v for k, v in params.items() if v})
        return f"vless://{n['uuid']}@{n['server']}:{n['server_port']}?{q}#{urllib.parse.quote(tag)}"
    elif typ == "hysteria2":
        t = n.get("tls", {})
        p = n.get("password") or n.get("uuid", "")
        params = {
            "insecure": "1" if t.get("insecure") else "0",
            "sni": t.get("server_name", ""),
            "alpn": (t.get("alpn") or [""])[0],
        }
        q = urllib.parse.urlencode({k: v for k, v in params.items() if v})
        return f"hysteria2://{p}@{n['server']}:{n['server_port']}?{q}#{urllib.parse.quote(tag)}"
    return None


# ==================== Clash Meta 配置 ====================
def to_clash_proxy(n: dict, prefix: str) -> Optional[Dict[str, Any]]:
    typ = n.get("type")
    name = f"{prefix}{n.get('tag', 'node')}"
    if typ == "vless":
        t = n.get("tls", {})
        r = t.get("reality", {})
        proxy = {
            "name": name,
            "type": "vless",
            "server": n["server"],
            "port": n["server_port"],
            "uuid": n["uuid"],
            "network": "tcp",
            "tls": True,
            "udp": True,
            "flow": n.get("flow") or "",
            "servername": t.get("server_name", ""),
            "client-fingerprint": t.get("utls", {}).get("fingerprint", "chrome"),
            "reality-opts": {
                "public-key": r.get("public_key", ""),
                "short-id": r.get("short_id", ""),
            },
        }
        if not proxy["flow"]:
            del proxy["flow"]
        return proxy
    elif typ == "hysteria2":
        t = n.get("tls", {})
        p = n.get("password") or n.get("uuid", "")
        proxy = {
            "name": name,
            "type": "hysteria2",
            "server": n["server"],
            "port": n["server_port"],
            "password": p,
            "sni": t.get("server_name", ""),
            "skip-cert-verify": bool(t.get("insecure")),
        }
        alpn = t.get("alpn")
        if alpn:
            proxy["alpn"] = alpn if isinstance(alpn, list) else [alpn]
        return proxy
    return None


def build_clash(proxies: List[Dict[str, Any]]) -> str:
    proxy_names = [p["name"] for p in proxies]
    config = {
        "mixed-port": 7890,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "external-controller": "127.0.0.1:9090",
        "dns": {
            "enable": True,
            "enhanced-mode": "fake-ip",
            "nameserver": ["8.8.8.8", "1.1.1.1"],
            "fallback": ["https://dns.google/dns-query"],
        },
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "🚀 节点选择",
                "type": "select",
                "proxies": ["♻️ 自动选择", "DIRECT"] + proxy_names,
            },
            {
                "name": "♻️ 自动选择",
                "type": "url-test",
                "proxies": proxy_names,
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
            },
            {
                "name": "🌍 国外媒体",
                "type": "select",
                "proxies": ["🚀 节点选择", "♻️ 自动选择"] + proxy_names,
            },
            {
                "name": "🍎 苹果服务",
                "type": "select",
                "proxies": ["DIRECT", "🚀 节点选择"],
            },
            {
                "name": "🎯 全球直连",
                "type": "select",
                "proxies": ["DIRECT", "🚀 节点选择"],
            },
            {
                "name": "🛑 全球拦截",
                "type": "select",
                "proxies": ["REJECT", "DIRECT"],
            },
        ],
        "rules": [
            "DOMAIN-SUFFIX,local,DIRECT",
            "IP-CIDR,127.0.0.0/8,DIRECT",
            "IP-CIDR,192.168.0.0/16,DIRECT",
            "IP-CIDR,10.0.0.0/8,DIRECT",
            "IP-CIDR,172.16.0.0/12,DIRECT",
            "GEOIP,CN,🎯 全球直连",
            "MATCH,🚀 节点选择",
        ],
    }
    # 简单 YAML 输出（避免引入 PyYAML 依赖）
    import yaml  # type: ignore

    return yaml.dump(config, allow_unicode=True, sort_keys=False, default_flow_style=False)


# ==================== sing-box 配置 ====================
def to_singbox_outbound(n: dict, prefix: str) -> Optional[Dict[str, Any]]:
    typ = n.get("type")
    tag = f"{prefix}{n.get('tag', 'node')}"
    if typ == "vless":
        t = n.get("tls", {})
        r = t.get("reality", {})
        outbound = {
            "type": "vless",
            "tag": tag,
            "server": n["server"],
            "server_port": n["server_port"],
            "uuid": n["uuid"],
            "flow": n.get("flow") or "",
            "tls": {
                "enabled": True,
                "server_name": t.get("server_name", ""),
                "utls": {
                    "enabled": True,
                    "fingerprint": t.get("utls", {}).get("fingerprint", "chrome"),
                },
                "reality": {
                    "enabled": True,
                    "public_key": r.get("public_key", ""),
                    "short_id": r.get("short_id", ""),
                },
            },
        }
        if not outbound["flow"]:
            del outbound["flow"]
        return outbound
    elif typ == "hysteria2":
        t = n.get("tls", {})
        p = n.get("password") or n.get("uuid", "")
        outbound = {
            "type": "hysteria2",
            "tag": tag,
            "server": n["server"],
            "server_port": n["server_port"],
            "password": p,
            "tls": {
                "enabled": True,
                "server_name": t.get("server_name", ""),
                "insecure": bool(t.get("insecure")),
            },
        }
        alpn = t.get("alpn")
        if alpn:
            outbound["tls"]["alpn"] = alpn if isinstance(alpn, list) else [alpn]
        return outbound
    return None


def build_singbox(outbounds: List[Dict[str, Any]]) -> dict:
    tags = [o["tag"] for o in outbounds]
    return {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "google", "address": "8.8.8.8"},
                {"tag": "local", "address": "local", "detour": "direct"},
            ],
            "rules": [{"outbound": "any", "server": "google"}],
            "final": "google",
        },
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 7890,
            }
        ],
        "outbounds": outbounds
        + [
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
            {
                "type": "selector",
                "tag": "proxy",
                "outbounds": tags + ["direct"],
                "default": tags[0] if tags else "direct",
            },
            {
                "type": "urltest",
                "tag": "auto",
                "outbounds": tags,
                "url": "http://www.gstatic.com/generate_204",
                "interval": "5m",
            },
        ],
        "route": {
            "rules": [
                {"protocol": "dns", "action": "hijack-dns"},
                {"geoip": "cn", "outbound": "direct"},
                {"geoip": "private", "outbound": "direct"},
            ],
            "final": "proxy",
            "auto_detect_interface": True,
        },
    }


# ==================== 主流程 ====================
def main():
    all_uris: List[str] = []
    all_clash: List[Dict[str, Any]] = []
    all_singbox: List[Dict[str, Any]] = []

    for is_cn, label in [(True, "[CN]"), (False, "[Global]")]:
        region = "国内" if is_cn else "国际"
        print(f"[*] 获取 {region} 节点...")
        try:
            cfg = fetch(is_cn)
            nodes = [
                n
                for n in cfg.get("outbounds", [])
                if n.get("type") in ("vless", "hysteria2")
            ]
            for n in nodes:
                uri = make_uri(n, label)
                if uri:
                    all_uris.append(uri)
                clash_p = to_clash_proxy(n, label)
                if clash_p:
                    all_clash.append(clash_p)
                sb = to_singbox_outbound(n, label)
                if sb:
                    all_singbox.append(sb)
            print(f"    [+] {len(nodes)} 个节点")
        except Exception as e:
            print(f"    [失败] {e}")

    if not all_uris:
        sys.exit("错误：未获取到任何节点")

    base_dir = get_output_dir()
    os.makedirs(base_dir, exist_ok=True)

    # 1. 纯订阅文本
    txt_path = os.path.join(base_dir, OUT_TXT)
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("\n".join(all_uris) + "\n")
    print(f"[+] 纯订阅已保存: {txt_path}  ({len(all_uris)} 条)")

    # 2. Clash Meta
    try:
        import yaml  # noqa: F401
        clash_path = os.path.join(base_dir, OUT_CLASH)
        with open(clash_path, "w", encoding="utf-8") as f:
            f.write(build_clash(all_clash))
        print(f"[+] Clash 配置已保存: {clash_path}")
    except ImportError:
        print("[!] 未安装 PyYAML，跳过 Clash 输出（pip install pyyaml）")

    # 3. sing-box
    sb_path = os.path.join(base_dir, OUT_SINGBOX)
    with open(sb_path, "w", encoding="utf-8") as f:
        json.dump(build_singbox(all_singbox), f, ensure_ascii=False, indent=2)
    print(f"[+] sing-box 配置已保存: {sb_path}")

    print(f"\n✅ 全部完成，共 {len(all_uris)} 个节点")


if __name__ == "__main__":
    main()
