#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HedgeVPN（刺猬VPN）节点抓取 + 自动注册
=====================================
每次运行自动注册一个试用账号（60 分钟全地区权益），拉取全部 21 个地区的节点，
输出 4 种订阅格式：

    hedgevpn_nodes.txt        纯分享链接（通用）
    hedgevpn_sub_b64.txt      Base64 订阅（v2rayN / Shadowrocket / Bettbox 通用）
    hedgevpn_singbox.json     sing-box 配置（Bettbox / SFI / sing-box 客户端）
    hedgevpn_clash.yaml       Clash Meta / Mihomo 配置

环境变量（可选，不填则自动注册）：
    HEDGE_ACCOUNT    已有账号
    HEDGE_PASSWORD   已有密码
    OUT_DIR          输出目录（默认当前目录）

依赖：pip install pycryptodome pyyaml
"""

import base64
import hashlib
import json
import os
import random
import string
import sys
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

import requests
import urllib3

urllib3.disable_warnings()

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    sys.exit("缺少依赖：pip install pycryptodome")

# ---------------------------------------------------------------- 常量

BASE = "https://47.75.118.221:2083"
PKG_ID = "com.hedge.group"
CHANNEL = "666666"
VERSION = "3.1.0"

P_FIRST = "/api/v1/external/firstOpen"
P_REGISTER = "/api/v1/external/account/register"
P_LOGIN = "/api/v1/external/account/login"
P_PROFILE = "/api/v1/internal/account/profile"
P_AREA = "/api/v1/internal/proxy/area/list/v2"
P_NODES = "/api/v1/internal/proxy/node/list"
P_CONFIG = "/api/v1/internal/proxy/node/config"

ALPHABET = "abcdefgh123456789ABCDEFGHJKLMNPQRSTUVWXYZijkmnopqrstuvwxyz"
UA = "Dart/3.9 (dart:io)"

OUT = os.environ.get("OUT_DIR") or "."


# ---------------------------------------------------------------- 编码/加密

def b58_decode(s: str) -> str:
    n = 0
    for ch in s:
        i = ALPHABET.find(ch)
        if i < 0:
            raise ValueError("bad char")
        n = n * 58 + i
    raw = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    pad_n = 0
    for ch in s:
        if ch == ALPHABET[0]:
            pad_n += 1
        else:
            break
    return ("\x00" * pad_n + raw.decode("utf-8", "replace")).lstrip("\x00")


def _derive(seed: bytes) -> Tuple[bytes, bytes]:
    d = hashlib.sha256(seed).digest()
    w = [d[i * 4:(i + 1) * 4] for i in range(8)]
    return (b"".join(w[i] for i in range(8) if i % 2 == 0),
            b"".join(w[i] for i in range(8) if i % 2 == 1))


def enc(obj: Any) -> str:
    seed = os.urandom(16)
    key, iv = _derive(seed)
    raw = obj if isinstance(obj, str) else json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(raw.encode(), 16))
    return base64.b64encode(seed + ct).decode()


def looks_enc(s: Any) -> bool:
    if not isinstance(s, str) or len(s) < 44 or len(s) % 4:
        return False
    if not all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in s):
        return False
    n = len(s) // 4 * 3 - (2 if s.endswith("==") else 1 if s.endswith("=") else 0)
    return n > 16 and (n - 16) % 16 == 0


def dec(s: str) -> str:
    raw = base64.b64decode(s)
    key, iv = _derive(raw[:16])
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(raw[16:]), 16).decode("utf-8", "replace")


def md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


# ---------------------------------------------------------------- 客户端

class Client:
    def __init__(self, account: str = "", password: str = ""):
        self.account = account
        self.password = password
        self.uuid = "".join(random.choice("0123456789abcdef") for _ in range(32))
        self.dkey = md5(f"{self.uuid}|{VERSION}")
        self.sess = ""
        self.tok = ""
        self.s = requests.Session()
        self.s.verify = False
        self.s.headers.update({"User-Agent": UA})

    def _now(self) -> int:
        # 服务端拒绝"未来"时间戳，提前 2 秒
        return int((time.time() - 2) * 1_000_000)

    def post(self, path: str, inner: Any, retry: int = 6) -> Dict[str, Any]:
        last = {}
        for i in range(retry):
            ts = self._now()
            if callable(inner):
                inner = inner(ts)
            body = {"data": enc(inner), "channelId": CHANNEL, "timestamp": ts,
                    "appPkgId": PKG_ID, "version": VERSION}
            raw = json.dumps(body, separators=(",", ":"), ensure_ascii=False)
            hdr = {"Content-Type": "application/json", "x-session": self.sess,
                   "x-uuid": self.uuid,
                   "x-sign": md5(raw + self.tok) if self.tok else md5(raw)}
            if self.tok:
                hdr["Authorization"] = "Bearer " + self.tok
            try:
                r = self.s.post(BASE + path, data=raw.encode(), headers=hdr, timeout=25)
                j = r.json()
            except Exception as e:
                last = {"code": -1, "msg": str(e)[:80]}
                time.sleep(1 + i)
                continue
            if j.get("code") == 30002 and i < retry - 1:
                time.sleep(0.4 + i * 0.3)
                last = j
                continue
            return j
        return last

    @staticmethod
    def data(j: Dict[str, Any]) -> Any:
        d = j.get("data")
        if isinstance(d, str) and looks_enc(d):
            try:
                return json.loads(dec(d))
            except Exception:
                return d
        return d

    def first_open(self) -> Dict[str, Any]:
        return self.post(P_FIRST, {"deviceKey": self.dkey, "platform": 2})

    def register(self) -> bool:
        if not self.account:
            self.account = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))
            self.password = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))
        j = self.post(P_REGISTER, {"account": self.account, "password": self.password,
                                   "invitorUid": "", "deviceKey": self.dkey})
        ok = j.get("code") == 200
        print(f"  注册 {self.account} / {self.password} → {j.get('code')} {j.get('msg')}")
        return ok

    def login(self) -> bool:
        def build(ts):
            return {"account": self.account, "checkSum": md5(f"{ts}{self.password}"),
                    "autoLogin": False, "kickoffSessionId": None, "deviceKey": self.dkey}
        j = self.post(P_LOGIN, build)
        if j.get("code") != 200:
            print(f"  登录失败 {j.get('code')} {j.get('msg')}")
            return False
        d = self.data(j) or {}
        sl = d.get("successLogin") or d
        self.sess = sl.get("sessionId") or ""
        self.tok = sl.get("authToken") or ""
        return bool(self.sess)

    def profile(self) -> Any:
        return self.data(self.post(P_PROFILE, {}))

    def areas(self) -> List[Tuple[str, str]]:
        d = self.data(self.post(P_AREA, {}))
        out = []
        if isinstance(d, dict):
            for g in d.get("list", []):
                for a in g.get("areaList", []):
                    out.append((str(a.get("areaId")), a.get("areaName") or ""))
        return out

    def node_ids(self, area_id: Optional[str] = None) -> List[str]:
        d = self.data(self.post(P_NODES, {} if area_id is None else {"areaId": area_id}))
        if not isinstance(d, dict):
            return []
        return [str(n["nodeId"]) for n in d.get("list", []) if n.get("nodeId")]

    def node_config(self, nid: str) -> List[str]:
        d = self.data(self.post(P_CONFIG, {"nodeId": nid}))
        urls = []
        if isinstance(d, dict):
            for item in d.get("list", []) or []:
                c = item.get("config")
                if isinstance(c, str):
                    try:
                        v = b58_decode(c).strip()
                        if v.startswith(("vless://", "vmess://", "trojan://", "ss://")):
                            urls.append(v)
                    except Exception:
                        pass
            c = d.get("config")
            if isinstance(c, str):
                try:
                    v = b58_decode(c).strip()
                    if v.startswith(("vless://", "vmess://", "trojan://", "ss://")):
                        urls.append(v)
                except Exception:
                    pass
        return list(dict.fromkeys(urls))


# ---------------------------------------------------------------- 解析

def parse_vless(u: str) -> Optional[Dict[str, Any]]:
    if not u.startswith("vless://"):
        return None
    rest = u[8:]
    name = ""
    if "#" in rest:
        rest, name = rest.split("#", 1)
        name = urllib.parse.unquote(name)
    q = {}
    if "?" in rest:
        rest, qs = rest.split("?", 1)
        q = dict(urllib.parse.parse_qsl(qs))
    if "@" not in rest:
        return None
    cred, hp = rest.rsplit("@", 1)
    host, _, port = hp.rpartition(":")
    return {
        "uuid": urllib.parse.unquote(cred), "server": host, "port": int(port or 443),
        "name": name or f"{host}:{port}", "q": q,
        "sni": q.get("sni", ""), "pbk": q.get("pbk", ""), "sid": q.get("sid", ""),
        "fp": q.get("fp", "chrome"), "flow": q.get("flow", ""),
        "net": q.get("type", "tcp"), "security": q.get("security", "none"),
        "seed": q.get("seed", ""), "header": q.get("headerType", "none"),
    }


# ---------------------------------------------------------------- 输出格式

def to_singbox(nodes: List[Dict[str, Any]]) -> Dict[str, Any]:
    """生成 sing-box 配置：tun + 详细分流（Bettbox / SFI 可直接导入）"""
    outs = []
    for n in nodes:
        ob = {
            "type": "vless", "tag": n["name"], "server": n["server"],
            "server_port": n["port"], "uuid": n["uuid"],
        }
        if n["flow"]:
            ob["flow"] = n["flow"]
        if n["security"] in ("reality", "tls"):
            tls = {"enabled": True, "server_name": n["sni"] or n["server"]}
            if n["fp"]:
                tls["utls"] = {"enabled": True, "fingerprint": n["fp"]}
            if n["security"] == "reality" and n["pbk"]:
                tls["reality"] = {"enabled": True, "public_key": n["pbk"], "short_id": n["sid"]}
            ob["tls"] = tls
        if n["net"] == "kcp":
            tr = {"type": "kcp"}
            if n["seed"]:
                tr["seed"] = n["seed"]
            if n["header"]:
                tr["header"] = {"type": n["header"]}
            ob["transport"] = tr
        elif n["net"] in ("ws", "grpc", "http", "httpupgrade"):
            tr = {"type": n["net"]}
            if n["net"] == "grpc":
                tr["service_name"] = n["q"].get("serviceName", "")
            else:
                tr["path"] = n["q"].get("path", "/")
                if n["q"].get("host"):
                    tr["host"] = n["q"]["host"]
            ob["transport"] = tr
        outs.append(ob)

    tags = [o["tag"] for o in outs]
    all_sel = ["PROXY", "AUTO"] + tags

    outs += [
        {"type": "selector", "tag": "PROXY", "outbounds": ["AUTO"] + tags, "default": "AUTO"},
        {"type": "urltest", "tag": "AUTO", "outbounds": tags,
         "url": "https://www.gstatic.com/generate_204", "interval": "3m", "tolerance": 50},
        {"type": "selector", "tag": "STREAMING", "outbounds": ["PROXY", "AUTO"] + tags,
         "default": "PROXY"},
        {"type": "selector", "tag": "AI", "outbounds": ["PROXY", "AUTO"] + tags, "default": "PROXY"},
        {"type": "selector", "tag": "TELEGRAM", "outbounds": ["PROXY", "AUTO"] + tags,
         "default": "PROXY"},
        {"type": "selector", "tag": "GAME", "outbounds": ["DIRECT", "PROXY"] + tags,
         "default": "DIRECT"},
        {"type": "direct", "tag": "DIRECT"},
        {"type": "block", "tag": "REJECT"},
        {"type": "dns", "tag": "dns-out"},
    ]

    # ---- 规则集（jsDelivr 镜像，国内可直连）----
    def rs(kind: str, name: str, tag: str) -> Dict[str, Any]:
        return {
            "type": "remote", "tag": tag, "format": "binary",
            "url": f"https://cdn.jsdelivr.net/gh/SagerNet/sing-{kind}@rule-set/{name}.srs",
            "download_detour": "PROXY", "update_interval": "1d",
        }

    rule_sets = [
        rs("geosite", "geosite-category-ads-all", "ads"),
        rs("geosite", "geosite-cn", "cn-domain"),
        rs("geosite", "geosite-geolocation-cn", "cn-domain-2"),
        rs("geosite", "geosite-geolocation-!cn", "global-domain"),
        rs("geoip", "geoip-cn", "cn-ip"),
        rs("geosite", "geosite-apple", "apple"),
        rs("geosite", "geosite-microsoft", "microsoft"),
        rs("geosite", "geosite-google", "google"),
        rs("geosite", "geosite-youtube", "youtube"),
        rs("geosite", "geosite-netflix", "netflix"),
        rs("geosite", "geosite-disney", "disney"),
        rs("geosite", "geosite-hbo", "hbo"),
        rs("geosite", "geosite-primevideo", "primevideo"),
        rs("geosite", "geosite-spotify", "spotify"),
        rs("geosite", "geosite-tiktok", "tiktok"),
        rs("geosite", "geosite-openai", "openai"),
        rs("geosite", "geosite-anthropic", "anthropic"),
        rs("geosite", "geosite-google-gemini", "gemini"),
        rs("geosite", "geosite-telegram", "telegram-domain"),
        rs("geosite", "geosite-category-games", "games"),
    ]

    route_rules = [
        # DNS 流量交给内部 dns 出站
        {"protocol": "dns", "outbound": "dns-out"},
        # 私有 / 局域网 / 链路本地
        {"ip_is_private": True, "outbound": "DIRECT"},
        # 广告与跟踪
        {"rule_set": "ads", "outbound": "REJECT"},
        # 本地服务（国内常见 App 推送、NTP 等）
        {"port": [123], "outbound": "DIRECT"},
        # 国内域名 / IP 直连
        {"rule_set": ["cn-domain", "cn-domain-2"], "outbound": "DIRECT"},
        {"rule_set": "cn-ip", "outbound": "DIRECT"},
        # 苹果 / 微软国内 CDN 直连（速度更好）
        {"rule_set": "apple", "outbound": "DIRECT"},
        {"rule_set": "microsoft", "outbound": "DIRECT"},
        # 流媒体
        {"rule_set": ["netflix", "disney", "hbo", "primevideo", "spotify", "tiktok"],
         "outbound": "STREAMING"},
        {"rule_set": "youtube", "outbound": "STREAMING"},
        # AI 服务
        {"rule_set": ["openai", "anthropic", "gemini"], "outbound": "AI"},
        # Telegram 走独立出口（UDP 需代理）
        {"rule_set": "telegram-domain", "outbound": "TELEGRAM"},
        # 游戏平台
        {"rule_set": "games", "outbound": "GAME"},
        # 其余境外域名
        {"rule_set": "google", "outbound": "PROXY"},
        {"rule_set": "global-domain", "outbound": "PROXY"},
    ]

    return {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "dns-cn", "type": "udp", "server": "223.5.5.5"},
                {"tag": "dns-cn2", "type": "udp", "server": "119.29.29.29"},
                {"tag": "dns-remote", "type": "https", "server": "1.1.1.1",
                 "server_port": 443, "path": "/dns-query", "detour": "PROXY"},
            ],
            "rules": [
                {"rule_set": "ads", "action": "reject"},
                {"rule_set": ["cn-domain", "cn-domain-2"], "server": "dns-cn"},
                {"rule_set": "cn-ip", "server": "dns-cn"},
                {"rule_set": ["netflix", "disney", "hbo", "primevideo", "youtube"],
                 "server": "dns-remote"},
                {"rule_set": ["openai", "anthropic", "gemini", "telegram-domain"],
                 "server": "dns-remote"},
            ],
            "final": "dns-remote",
            "strategy": "prefer_ipv4",
            "disable_cache": False,
        },
        "inbounds": [
            {"type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30"], "mtu": 9000,
             "auto_route": True, "strict_route": True, "stack": "mixed",
             "sniff": True, "sniff_override_destination": False},
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080,
             "sniff": True},
        ],
        "outbounds": outs,
        "route": {
            "rules": route_rules,
            "rule_set": rule_sets,
            "final": "PROXY",
            "auto_detect_interface": True,
        },
        "experimental": {
            "cache_file": {"enabled": True},
            "clash_api": {"external_controller": "127.0.0.1:9090"},
        },
    }


def to_clash(nodes: List[Dict[str, Any]]) -> str:
    """生成完整 Clash Meta (mihomo) 配置：节点 + 策略组 + 详细分流 + DNS"""
    L: List[str] = []
    a = L.append

    a("# HedgeVPN / Clash Meta (mihomo) 配置 - 自动生成")
    a("# 适用：Clash Verge Rev / Mihomo Party / Clash Meta for Android / FlClash / OpenClash")
    a("")
    a("mixed-port: 7890")
    a("socks-port: 7891")
    a("port: 7892")
    a("allow-lan: false")
    a("bind-address: '*'")
    a("mode: rule")
    a("log-level: info")
    a("ipv6: true")
    a("unified-delay: true")
    a("tcp-concurrent: true")
    a("find-process-mode: 'off'")
    a("global-client-fingerprint: chrome")
    a("external-controller: 127.0.0.1:9090")
    a("")
    a("profile:")
    a("  store-selected: true")
    a("  store-fake-ip: true")
    a("")

    # ---------------- geodata（jsDelivr 镜像，国内外均可下载） ----------------
    a("geodata-mode: true")
    a("geodata-loader: standard")
    a("geo-auto-update: true")
    a("geo-update-interval: 24")
    a("geox-url:")
    a("  geoip: 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat'")
    a("  geosite: 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat'")
    a("  mmdb: 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb'")
    a("")

    # ---------------- DNS 分流 ----------------
    a("dns:")
    a("  enable: true")
    a("  listen: 0.0.0.0:1053")
    a("  ipv6: true")
    a("  prefer-h3: false")
    a("  respect-rules: false")
    a("  enhanced-mode: fake-ip")
    a("  fake-ip-range: 198.18.0.1/16")
    a("  fake-ip-filter-mode: blacklist")
    a("  fake-ip-filter:")
    for x in ["'*.lan'", "'*.local'", "'*.localdomain'", "'localhost.ptlogin2.qq.com'",
              "'+.msftconnecttest.com'", "'+.msftncsi.com'", "'time.*.com'",
              "'ntp.*.com'", "'+.pool.ntp.org'", "'stun.*.*'", "'+.stun.*.*'"]:
        a("    - " + x)
    a("  default-nameserver:")
    a("    - 223.5.5.5")
    a("    - 119.29.29.29")
    a("  proxy-server-nameserver:")
    a("    - 'https://dns.alidns.com/dns-query'")
    a("    - 'https://doh.pub/dns-query'")
    a("  nameserver:")
    a("    - 'https://dns.alidns.com/dns-query'")
    a("    - 'https://doh.pub/dns-query'")
    a("    - 'https://223.5.5.5/dns-query'")
    a("  nameserver-policy:")
    a("    'geosite:cn,private':")
    a("      - 'https://dns.alidns.com/dns-query'")
    a("      - 'https://doh.pub/dns-query'")
    a("    'geosite:netflix,disney,hbo,primevideo,youtube,tiktok,spotify':")
    a("      - 'https://1.1.1.1/dns-query'")
    a("      - 'https://8.8.8.8/dns-query'")
    a("    'geosite:openai,anthropic,telegram':")
    a("      - 'https://1.1.1.1/dns-query'")
    a("      - 'https://8.8.8.8/dns-query'")
    a("")

    # ---------------- 节点 ----------------
    a("proxies:")
    names: List[str] = []
    used: Dict[str, int] = {}
    for n in nodes:
        nm = n["name"]
        if nm in used:
            used[nm] += 1
            nm = f"{nm} #{used[nm]}"
        else:
            used[nm] = 1
        names.append(nm)

        a(f"  - name: {json.dumps(nm, ensure_ascii=False)}")
        a("    type: vless")
        a(f"    server: {n['server']}")
        a(f"    port: {n['port']}")
        a(f"    uuid: {json.dumps(str(n['uuid']))}")
        a("    udp: true")
        a("    tfo: false")
        a("    skip-cert-verify: false")
        if n["flow"]:
            a(f"    flow: {n['flow']}")
        if n["security"] in ("reality", "tls"):
            a("    tls: true")
            a(f"    servername: {json.dumps(n['sni'] or n['server'], ensure_ascii=False)}")
            if n["fp"]:
                a(f"    client-fingerprint: {n['fp']}")
            else:
                a("    client-fingerprint: chrome")
            if n["security"] == "reality" and n["pbk"]:
                a("    reality-opts:")
                a(f"      public-key: {json.dumps(n['pbk'])}")
                a(f"      short-id: {json.dumps(n['sid'] or '')}")
        a(f"    network: {n['net']}")
        if n["net"] == "kcp":
            a("    kcp-opts:")
            if n["seed"]:
                a(f"      seed: {json.dumps(n['seed'])}")
            a("      header:")
            a(f"        type: {n['header'] or 'none'}")
        if n["net"] == "ws":
            a("    ws-opts:")
            a(f"      path: {json.dumps(n['q'].get('path', '/'))}")
            if n["q"].get("host"):
                a("      headers:")
                a(f"        Host: {json.dumps(n['q']['host'])}")
        if n["net"] == "grpc":
            a("    grpc-opts:")
            a(f"      grpc-service-name: {json.dumps(n['q'].get('serviceName', ''))}")
        if n["net"] in ("http", "h2"):
            a("    h2-opts:")
            a(f"      path: {json.dumps(n['q'].get('path', '/'))}")
            if n["q"].get("host"):
                a("      host:")
                a(f"        - {json.dumps(n['q']['host'])}")
    a("")

    # ---------------- 策略组 ----------------
    all_nodes = ", ".join(json.dumps(x, ensure_ascii=False) for x in names)
    a("proxy-groups:")
    a("  - name: '🚀 节点选择'")
    a("    type: select")
    a("    proxies:")
    for g in ["♻️ 自动选择", "🎬 流媒体", "🤖 AI服务", "📲 电报消息", "🎮 游戏平台", "🎯 直连"]:
        a(f"      - '{g}'")
    for x in names:
        a(f"      - {json.dumps(x, ensure_ascii=False)}")
    a("")
    a("  - name: '♻️ 自动选择'")
    a("    type: url-test")
    a("    url: 'http://www.gstatic.com/generate_204'")
    a("    interval: 300")
    a("    tolerance: 50")
    a("    lazy: false")
    a("    proxies:")
    for x in names:
        a(f"      - {json.dumps(x, ensure_ascii=False)}")
    a("")
    a("  - name: '🎬 流媒体'")
    a("    type: select")
    a("    proxies:")
    for g in ["♻️ 自动选择"]:
        a(f"      - '{g}'")
    for x in names:
        a(f"      - {json.dumps(x, ensure_ascii=False)}")
    a("")
    a("  - name: '🤖 AI服务'")
    a("    type: select")
    a("    proxies:")
    for g in ["♻️ 自动选择"]:
        a(f"      - '{g}'")
    for x in names:
        a(f"      - {json.dumps(x, ensure_ascii=False)}")
    a("")
    a("  - name: '📲 电报消息'")
    a("    type: select")
    a("    proxies:")
    for g in ["♻️ 自动选择"]:
        a(f"      - '{g}'")
    for x in names:
        a(f"      - {json.dumps(x, ensure_ascii=False)}")
    a("")
    a("  - name: '🎮 游戏平台'")
    a("    type: select")
    a("    proxies:")
    for g in ["🎯 直连", "♻️ 自动选择"]:
        a(f"      - '{g}'")
    for x in names:
        a(f"      - {json.dumps(x, ensure_ascii=False)}")
    a("")
    a("  - name: '🎯 直连'")
    a("    type: select")
    a("    proxies:")
    a("      - DIRECT")
    for x in names:
        a(f"      - {json.dumps(x, ensure_ascii=False)}")
    a("")
    a("  - name: '🛑 广告拦截'")
    a("    type: select")
    a("    proxies:")
    a("      - REJECT")
    a("      - DIRECT")
    a("")

    # ---------------- 规则 ----------------
    rules: List[str] = []
    # 本地 / 私有网段
    rules += [
        "DOMAIN-SUFFIX,local,DIRECT",
        "DOMAIN-SUFFIX,lan,DIRECT",
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
        "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
        "IP-CIDR,169.254.0.0/16,DIRECT,no-resolve",
        "IP-CIDR6,fc00::/7,DIRECT,no-resolve",
        "IP-CIDR6,fe80::/10,DIRECT,no-resolve",
        "DST-PORT,123,DIRECT",
    ]
    # 广告
    rules += [
        "GEOSITE,category-ads-all,🛑 广告拦截",
    ]
    # AI（gemini 必须先于 google）
    rules += [
        "DOMAIN-SUFFIX,gemini.google.com,🤖 AI服务",
        "DOMAIN-SUFFIX,bard.google.com,🤖 AI服务",
        "DOMAIN-SUFFIX,openai.com,🤖 AI服务",
        "DOMAIN-SUFFIX,chatgpt.com,🤖 AI服务",
        "DOMAIN-SUFFIX,oaistatic.com,🤖 AI服务",
        "DOMAIN-SUFFIX,oaiusercontent.com,🤖 AI服务",
        "DOMAIN-SUFFIX,sora.com,🤖 AI服务",
        "DOMAIN-SUFFIX,anthropic.com,🤖 AI服务",
        "DOMAIN-SUFFIX,claude.ai,🤖 AI服务",
        "DOMAIN-SUFFIX,perplexity.ai,🤖 AI服务",
        "DOMAIN-SUFFIX,midjourney.com,🤖 AI服务",
        "DOMAIN-SUFFIX,poe.com,🤖 AI服务",
        "GEOSITE,openai,🤖 AI服务",
        "GEOSITE,anthropic,🤖 AI服务",
    ]
    # 流媒体
    rules += [
        "DOMAIN-SUFFIX,netflix.com,🎬 流媒体",
        "DOMAIN-SUFFIX,nflxvideo.net,🎬 流媒体",
        "DOMAIN-SUFFIX,nflximg.net,🎬 流媒体",
        "DOMAIN-SUFFIX,nflxso.net,🎬 流媒体",
        "DOMAIN-SUFFIX,disneyplus.com,🎬 流媒体",
        "DOMAIN-SUFFIX,dssott.com,🎬 流媒体",
        "DOMAIN-SUFFIX,hbomax.com,🎬 流媒体",
        "DOMAIN-SUFFIX,hbomaxcdn.com,🎬 流媒体",
        "DOMAIN-SUFFIX,primevideo.com,🎬 流媒体",
        "DOMAIN-SUFFIX,spotify.com,🎬 流媒体",
        "DOMAIN-SUFFIX,scdn.co,🎬 流媒体",
        "DOMAIN-SUFFIX,tiktok.com,🎬 流媒体",
        "DOMAIN-SUFFIX,tiktokv.com,🎬 流媒体",
        "DOMAIN-SUFFIX,ibytedtos.com,🎬 流媒体",
        "DOMAIN-SUFFIX,youtube.com,🎬 流媒体",
        "DOMAIN-SUFFIX,youtu.be,🎬 流媒体",
        "DOMAIN-SUFFIX,googlevideo.com,🎬 流媒体",
        "DOMAIN-SUFFIX,ytimg.com,🎬 流媒体",
        "DOMAIN-SUFFIX,ggpht.com,🎬 流媒体",
        "GEOSITE,netflix,🎬 流媒体",
        "GEOSITE,disney,🎬 流媒体",
        "GEOSITE,hbo,🎬 流媒体",
        "GEOSITE,primevideo,🎬 流媒体",
        "GEOSITE,spotify,🎬 流媒体",
        "GEOSITE,tiktok,🎬 流媒体",
        "GEOSITE,youtube,🎬 流媒体",
    ]
    # Telegram
    rules += [
        "DOMAIN-SUFFIX,t.me,📲 电报消息",
        "DOMAIN-SUFFIX,telegram.org,📲 电报消息",
        "DOMAIN-SUFFIX,telegram.me,📲 电报消息",
        "DOMAIN-SUFFIX,telesco.pe,📲 电报消息",
        "DOMAIN-SUFFIX,tdesktop.com,📲 电报消息",
        "GEOSITE,telegram,📲 电报消息",
    ]
    # 游戏
    rules += [
        "GEOSITE,category-games,🎮 游戏平台",
    ]
    # 国内直连
    rules += [
        "GEOSITE,apple,DIRECT",
        "GEOSITE,microsoft,DIRECT",
        "DOMAIN-SUFFIX,cn,DIRECT",
        "GEOSITE,cn,DIRECT",
        "GEOSITE,geolocation-cn,DIRECT",
        "GEOIP,CN,DIRECT",
        "GEOSITE,google,🚀 节点选择",
        "GEOSITE,geolocation-!cn,🚀 节点选择",
        "MATCH,🚀 节点选择",
    ]

    a("rules:")
    for r in rules:
        a(f"  - {r}")
    a("")
    return "\n".join(L)


# ---------------------------------------------------------------- 主流程

def main() -> int:
    os.makedirs(OUT, exist_ok=True)
    acc = os.environ.get("HEDGE_ACCOUNT", "").strip()
    pwd = os.environ.get("HEDGE_PASSWORD", "").strip()

    cli = Client(acc, pwd)
    print(f"== 设备 {cli.uuid}")

    # 1) 激活设备
    cli.first_open()

    # 2) 登录，失败则注册
    if not (acc and pwd and cli.login()):
        print("== 自动注册新账号")
        cli.account = cli.password = ""
        if not cli.register():
            print("✘ 注册失败")
            return 1
        cli.login()

    if not cli.sess:
        print("✘ 登录失败")
        return 1

    pf = cli.profile() or {}
    import datetime
    exp = pf.get("vipExpireAt") or 0
    left = (exp - datetime.datetime.now().timestamp()) / 60
    print(f"== 账号 {cli.account} | 权益剩余 {left:.0f} 分钟")

    # 3) 21 个地区
    areas = cli.areas()
    print(f"== 地区 {len(areas)} 个")

    nodes: List[Dict[str, Any]] = []
    seen = set()
    for aid, aname in areas:
        ids = cli.node_ids(aid)
        if not ids:
            continue
        for nid in ids:
            for u in cli.node_config(nid):
                n = parse_vless(u)
                if not n:
                    continue
                key = (n["server"], n["port"], n["net"])
                if key in seen:
                    continue
                seen.add(key)
                n["name"] = f"{aname}-{n['server']}" + ("-kcp" if n["net"] == "kcp" else "")
                nodes.append(n)
        print(f"   {aname:14s} {len(ids)} 节点")

    # 默认节点补充
    for nid in cli.node_ids():
        for u in cli.node_config(nid):
            n = parse_vless(u)
            if n and (n["server"], n["port"], n["net"]) not in seen:
                seen.add((n["server"], n["port"], n["net"]))
                n["name"] = f"Default-{n['server']}" + ("-kcp" if n["net"] == "kcp" else "")
                nodes.append(n)

    if not nodes:
        print("✘ 未取到节点")
        return 1

    print(f"== 合计 {len(nodes)} 个节点")

    # 4) 输出
    def write(name: str, content: str):
        p = os.path.join(OUT, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"   → {name} ({len(content)} bytes)")

    lines = []
    for n in nodes:
        q = {k: v for k, v in n["q"].items() if v}
        lines.append(f"vless://{n['uuid']}@{n['server']}:{n['port']}?{urllib.parse.urlencode(q)}"
                     f"#{urllib.parse.quote(n['name'])}")
    sub = "\n".join(lines) + "\n"

    write("hedgevpn_nodes.txt", sub)
    write("hedgevpn_sub_b64.txt", base64.b64encode(sub.encode()).decode())
    write("hedgevpn_singbox.json", json.dumps(to_singbox(nodes), ensure_ascii=False, indent=2))
    write("hedgevpn_clash.yaml", to_clash(nodes))

    meta = {
        "account": cli.account,
        "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "vipExpireAt": exp,
        "areas": len(areas),
        "nodes": len(nodes),
    }
    write("hedgevpn_meta.json", json.dumps(meta, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
