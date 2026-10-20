#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
极点加速器（jidianvpn.com）节点订阅生成器
=========================================

Android 端是百度加固（libclash.so + baidup­rotect），无法静态分析；
但 PC 端是 Wails(Go+Vue) 未加固程序，从中还原出整套接口：

  POST /api/public/user/guestLogin   {"device_id": "<uuid>"} -> {"token","user"}
  GET  /api/customer/customerService/getCustomerServiceList
       -> [{sub_uuid, subject, service_status, ...}]
  GET  /api/public/sub/<sub_uuid 去连字符>/JIDIAN?type=ClashX&live_type=<n>
       -> 官方完整 Clash(Mihomo) 配置：3 个节点 + 374 条分流规则 + 8 个 rule-provider

live_type 对应线路：
  1 = 域名中转  anytls  igt84kf48fk4hq3.haowanlink.com:16407
  2 = IP 直连   ss-2022 (blake3-aes-256-gcm) + WebSocket

产物（当前目录）：
  jidian_clash.yaml     Mihomo / Bettbox（沿用官方全部规则）
  jidian_singbox.json   sing-box（anytls 与 ss-ws 均按真实协议转换）
  jidian_sub.txt        纯链接
  jidian_sub_b64.txt    base64 订阅
  jidian_nodes.json     节点元数据

环境变量：
  JIDIAN_DEVICE_ID   固定设备标识（不填则随机生成并缓存在 .jidian_session.json）

依赖：pyyaml
"""

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

import yaml

BASE = "https://api.apiooo.com"
SECTION = "JIDIAN"
SESSION = ".jidian_session.json"
LANES = [(1, "极点-中转"), (2, "极点-直连")]


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #
def http(method, path, token=None, body=None, timeout=25):
    headers = {"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
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
# 会话 / 登录
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
    d = os.environ.get("JIDIAN_DEVICE_ID") or sess.get("device_id")
    if not d:
        d = str(uuid.uuid4())
        sess["device_id"] = d
        save_session(sess)
    return d


def guest_login(sess):
    """游客登录；同一 device_id 复用同一账号"""
    code, text = http("POST", "/api/public/user/guestLogin",
                      body={"device_id": device_id(sess)})
    d = jload(text) or {}
    if code == 200 and d.get("code") == 0:
        data = d["data"]
        sess["token"] = data["token"]
        u = data.get("user") or {}
        sess["user"] = {"id": u.get("id"), "name": u.get("user_name")}
        save_session(sess)
        print(f"[+] 游客登录成功 uid={u.get('id')} {u.get('user_name')}")
        return data["token"]
    print(f"[!] 游客登录失败 HTTP {code}: {text[:160]}")
    return None


def get_sub_uuid(token):
    code, text = http("GET", "/api/customer/customerService/getCustomerServiceList",
                      token=token)
    d = jload(text) or {}
    if code != 200 or d.get("code") != 0:
        print(f"[!] 订阅列表失败: {text[:160]}")
        return None
    for svc in d.get("data") or []:
        if svc.get("sub_uuid"):
            print(f"[+] 套餐「{svc.get('subject')}」 sub_uuid={svc['sub_uuid']}")
            return svc["sub_uuid"]
    print("[!] 账号下没有订阅记录")
    return None


def fetch_sub(sub_uuid, live_type, retries=3):
    uid = sub_uuid.replace("-", "")
    path = f"/api/public/sub/{uid}/{SECTION}?type=ClashX&live_type={live_type}"
    for i in range(retries):
        code, text = http("GET", path, timeout=30)
        if code == 200 and text.strip():
            return text
        time.sleep(1.2 * (i + 1))
    return None


# --------------------------------------------------------------------------- #
# 格式转换
# --------------------------------------------------------------------------- #
def q(s):
    return urllib.parse.quote(str(s), safe="")


def clean_proxy(p, name):
    """去掉服务端塞进节点名的动态文案，换成稳定名字"""
    p = dict(p)
    p["name"] = name
    return p


def sb_outbound(p, tag):
    """Clash proxy -> sing-box outbound"""
    t = p.get("type")
    o = {"type": t, "tag": tag, "server": p.get("server"),
         "server_port": int(p.get("port") or 443)}

    if t == "anytls":
        o["password"] = p.get("password", "")
        o["tls"] = {"enabled": True,
                    "server_name": p.get("sni") or p.get("servername") or ""}
    elif t in ("ss", "shadowsocks"):
        o["type"] = "shadowsocks"
        o["method"] = p.get("cipher") or p.get("method")
        o["password"] = p.get("password", "")
        if (p.get("network") or "").lower() == "ws":
            ws = p.get("ws-opts") or {}
            tr = {"type": "ws", "path": ws.get("path") or "/"}
            host = (ws.get("headers") or {}).get("Host")
            if host:
                tr["headers"] = {"Host": host}
            o["transport"] = tr
    elif t == "vless":
        o["uuid"] = p.get("uuid")
        tls_on = bool(p.get("tls"))
        o["tls"] = {"enabled": tls_on,
                    "server_name": p.get("servername") or p.get("sni") or ""}
        if (p.get("network") or "").lower() == "ws":
            ws = p.get("ws-opts") or {}
            o["transport"] = {"type": "ws", "path": ws.get("path") or "/"}
    elif t == "vmess":
        o["uuid"] = p.get("uuid")
        o["security"] = p.get("cipher") or "auto"
        o["alter_id"] = int(p.get("alterId") or 0)
        if p.get("tls"):
            o["tls"] = {"enabled": True,
                        "server_name": p.get("servername") or p.get("sni") or ""}
        if (p.get("network") or "").lower() == "ws":
            ws = p.get("ws-opts") or {}
            o["transport"] = {"type": "ws", "path": ws.get("path") or "/"}
    elif t == "trojan":
        o["password"] = p.get("password", "")
        o["tls"] = {"enabled": True,
                    "server_name": p.get("sni") or p.get("servername") or ""}
    else:
        return None
    return o


def to_link(p, name):
    t = p.get("type")
    srv, port = p.get("server"), p.get("port")
    if t == "anytls":
        sni = p.get("sni") or p.get("servername") or ""
        return f"anytls://{q(p.get('password',''))}@{srv}:{port}/?sni={q(sni)}#{q(name)}"
    if t in ("ss", "shadowsocks"):
        method = p.get("cipher") or p.get("method") or ""
        userinfo = base64.urlsafe_b64encode(
            f"{method}:{p.get('password','')}".encode()).decode().rstrip("=")
        s = f"ss://{userinfo}@{srv}:{port}"
        if (p.get("network") or "").lower() == "ws":
            path = (p.get("ws-opts") or {}).get("path") or "/"
            plugin = urllib.parse.quote(f"v2ray-plugin;mode=websocket;path={path};tls", safe="")
            s += f"/?plugin={plugin}"
        return s + "#" + q(name)
    if t == "vless":
        sni = p.get("servername") or p.get("sni") or ""
        return (f"vless://{p.get('uuid')}@{srv}:{port}?encryption=none"
                f"&security={'tls' if p.get('tls') else 'none'}&sni={q(sni)}#{q(name)}")
    if t == "trojan":
        sni = p.get("sni") or ""
        return f"trojan://{q(p.get('password',''))}@{srv}:{port}?sni={q(sni)}#{q(name)}"
    return json.dumps(p, ensure_ascii=False)


def build_singbox(named):
    tags, obs = [], []
    for i, (name, p) in enumerate(named):
        tag = f"jidian-{i+1}"
        ob = sb_outbound(p, tag)
        if not ob:
            continue
        obs.append(ob)
        tags.append(tag)
    return {
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
        "outbounds": obs + [
            {"type": "selector", "tag": "proxy", "outbounds": tags + ["direct"]},
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


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #
def main():
    sess = load_session()
    token = guest_login(sess) or sess.get("token")
    if not token:
        print("[x] 登录失败")
        return 1

    sub_uuid = get_sub_uuid(token)
    if not sub_uuid:
        return 1

    named, meta, origin = [], [], None
    seen = set()
    for lt, label in LANES:
        text = fetch_sub(sub_uuid, lt)
        if not text:
            print(f"[!] live_type={lt} 拉取失败")
            continue
        try:
            cfg = yaml.safe_load(text)
        except Exception as e:
            print(f"[!] live_type={lt} YAML 解析失败: {e}")
            continue
        proxies = cfg.get("proxies") or []
        if not proxies:
            print(f"[!] live_type={lt} 无节点")
            continue
        p = proxies[0]
        key = (p.get("server"), p.get("port"))
        if key in seen:
            print(f"    - live_type={lt} 与已有线路重复，跳过")
            continue
        seen.add(key)
        if origin is None:
            origin = cfg          # 用第一份配置作骨架（含全部规则）
        named.append((label, clean_proxy(p, label)))
        meta.append({"name": label, "live_type": lt, "protocol": p.get("type"),
                     "server": p.get("server"), "port": p.get("port"),
                     "sni": p.get("sni") or p.get("servername"),
                     "cipher": p.get("cipher") or p.get("method")})
        print(f"    + {label} {p.get('type')} {p.get('server')}:{p.get('port')}")

    if not named or origin is None:
        print("[x] 没有可用节点")
        return 1

    # ---- 1. Clash：沿用官方骨架，只替换 proxies / proxy-groups ----
    clash = dict(origin)
    clash["proxies"] = [p for _, p in named]
    names = [n for n, _ in named]
    # 官方规则引用的是 QIANLI / 自动选择 / 故障转移，组名保持不变
    clash["proxy-groups"] = [
        {"name": "QIANLI", "type": "select", "proxies": names},
        {"name": "自动选择", "type": "url-test",
         "url": "http://www.gstatic.com/generate_204",
         "interval": 300, "tolerance": 50, "proxies": names},
        {"name": "故障转移", "type": "fallback",
         "url": "http://www.gstatic.com/generate_204",
         "interval": 300, "proxies": names},
    ]
    with open("jidian_clash.yaml", "w") as f:
        f.write("# 极点加速器（jidianvpn.com）订阅，规则沿用官方配置\n")
        yaml.safe_dump(clash, f, allow_unicode=True, sort_keys=False, width=4096)

    # ---- 2. sing-box ----
    with open("jidian_singbox.json", "w") as f:
        json.dump(build_singbox(named), f, ensure_ascii=False, indent=2)

    # ---- 3. 链接 ----
    links = [to_link(p, n) for n, p in named]
    with open("jidian_sub.txt", "w") as f:
        f.write("\n".join(links) + "\n")
    with open("jidian_sub_b64.txt", "w") as f:
        f.write(base64.b64encode("\n".join(links).encode()).decode() + "\n")

    # ---- 4. 元数据 ----
    with open("jidian_nodes.json", "w") as f:
        json.dump({"updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "sub_uuid": sub_uuid, "count": len(meta), "nodes": meta},
                  f, ensure_ascii=False, indent=2)

    print(f"[√] 生成 {len(named)} 个节点：jidian_clash.yaml / jidian_singbox.json / "
          f"jidian_sub.txt / jidian_sub_b64.txt / jidian_nodes.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
