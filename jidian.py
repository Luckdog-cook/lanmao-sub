#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
极点加速器（jidianvpn.com）节点订阅生成器
=========================================

Android 端是百度加固（libclash.so + baidup­rotect），无法静态分析；
PC 端是 Wails(Go+Vue) 未加固程序，从中还原出完整接口：

  POST /api/public/user/guestLogin                       {"device_id"} -> {"token","user"}
  GET  /api/customer/customerService/getCustomerServiceList
       -> [{id, sub_uuid, subject, ...}]
  GET  /api/customer/customerService/getSubscribeNodeList?id=<id>&live_type=<1|2>
       -> 节点清单（含 address/port/protocol/uuid/限速/负载/endpoint 链接）
  GET  /api/public/sub/<sub_uuid>/JIDIAN?type=ClashX&live_type=<n>
       -> 官方 Clash 配置骨架（374 条分流规则 + 8 个 rule-provider）

关键点：订阅 YAML 只下发 1 个节点，但 getSubscribeNodeList 会返回**全部** 15 个：
  live_type=1  直达线路：香港 5 / 日本 3 / 美国 3
  live_type=2  中转线路：香港 / 日本 / 美国 / 新加坡
其中 4 个 anyconnect「全局节点」Clash 与 sing-box 均不支持，会被跳过，实际可用 11 个。

产物（当前目录）：
  jidian_clash.yaml     Mihomo / Bettbox（沿用官方全部规则）
  jidian_singbox.json   sing-box
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
LANES = [(1, "直达"), (2, "中转")]
SUPPORTED = ("anytls", "shadowsocks", "ss")


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


def get_service(token):
    """返回 (subscribe_id, sub_uuid, subject)"""
    code, text = http("GET", "/api/customer/customerService/getCustomerServiceList",
                      token=token)
    d = jload(text) or {}
    if code != 200 or d.get("code") != 0:
        print(f"[!] 订阅列表失败: {text[:160]}")
        return None
    for svc in d.get("data") or []:
        if svc.get("sub_uuid") and svc.get("id"):
            print(f"[+] 套餐「{svc.get('subject')}」 id={svc['id']}")
            return svc["id"], svc["sub_uuid"], svc.get("subject")
    print("[!] 账号下没有订阅记录")
    return None


def get_nodes(token, sid, live_type):
    """完整的节点清单（这是 App 里真正用的接口）"""
    path = f"/api/customer/customerService/getSubscribeNodeList?id={sid}&live_type={live_type}"
    code, text = http("GET", path, token=token)
    d = jload(text) or {}
    if code != 200 or d.get("code") != 0:
        return []
    return d.get("data") or []


def fetch_sub_yaml(sub_uuid, live_type, retries=3):
    """官方 Clash 骨架（含全部分流规则），只用来取规则部分"""
    uid = sub_uuid.replace("-", "")
    path = f"/api/public/sub/{uid}/{SECTION}?type=ClashX&live_type={live_type}"
    for i in range(retries):
        code, text = http("GET", path, timeout=30)
        if code == 200 and text.strip():
            return text
        time.sleep(1.2 * (i + 1))
    return None


# --------------------------------------------------------------------------- #
# 解析
# --------------------------------------------------------------------------- #
def parse_endpoint(node):
    """把 endpoint 链接解析成统一结构"""
    ep = node.get("endpoint") or ""
    proto = (node.get("protocol") or "").lower()
    info = {"name": node.get("remarks") or "", "protocol": proto,
            "server": node.get("address"), "port": int(node.get("port") or 0),
            "sni": None, "method": None, "password": None,
            "speed_limit": node.get("node_speed_limit"),
            "load": node.get("load_percent"), "tags": node.get("tags"),
            "raw": ep}

    try:
        u = urllib.parse.urlparse(ep)
    except Exception:
        return info

    if proto == "anytls":
        info["password"] = urllib.parse.unquote(u.username or "")
        qs = urllib.parse.parse_qs(u.query)
        info["sni"] = (qs.get("sni") or [None])[0]
    elif proto in ("shadowsocks", "ss"):
        user = urllib.parse.unquote(u.username or "")
        try:
            dec = base64.b64decode(user + "=" * (-len(user) % 4)).decode()
            method, _, pwd = dec.partition(":")
            info["method"], info["password"] = method, pwd
        except Exception:
            pass
    return info


def clash_proxy(info):
    """生成 Mihomo proxy 条目"""
    t = info["protocol"]
    name = info["name"]
    if t == "anytls":
        return {"name": name, "type": "anytls", "server": info["server"],
                "port": info["port"], "password": info["password"],
                "udp": True, "sni": info["sni"], "tls": True,
                "client-fingerprint": "chrome"}
    if t in ("shadowsocks", "ss"):
        return {"name": name, "type": "ss", "server": info["server"],
                "port": info["port"], "cipher": info["method"],
                "password": info["password"], "udp": True,
                "network": "ws", "ws-opts": {"path": "/"}}
    return None


def sb_outbound(info, tag):
    t = info["protocol"]
    o = {"type": "anytls" if t == "anytls" else "shadowsocks", "tag": tag,
         "server": info["server"], "server_port": info["port"]}
    if t == "anytls":
        o["password"] = info["password"]
        o["tls"] = {"enabled": True, "server_name": info["sni"] or ""}
    else:
        o["method"] = info["method"]
        o["password"] = info["password"]
        o["transport"] = {"type": "ws", "path": "/"}
    return o


def to_link(info):
    t = info["protocol"]
    if t == "anytls":
        return (f"anytls://{urllib.parse.quote(info['password'] or '', safe='')}"
                f"@{info['server']}:{info['port']}/?sni={urllib.parse.quote(info['sni'] or '', safe='')}"
                f"#{urllib.parse.quote(info['name'], safe='')}")
    if t in ("shadowsocks", "ss"):
        body = base64.urlsafe_b64encode(
            f"{info['method']}:{info['password']}".encode()).decode().rstrip("=")
        return f"ss://{body}@{info['server']}:{info['port']}#" + urllib.parse.quote(info["name"], safe="")
    return ""


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #
def main():
    sess = load_session()
    token = guest_login(sess) or sess.get("token")
    if not token:
        print("[x] 登录失败")
        return 1

    svc = get_service(token)
    if not svc:
        return 1
    sid, sub_uuid, subject = svc

    # ---- 1. 收集全部节点 ----
    infos, seen, skipped = [], set(), []
    for lt, lane in LANES:
        nodes = get_nodes(token, sid, lt)
        print(f"[*] live_type={lt}（{lane}）返回 {len(nodes)} 个")
        for n in nodes:
            proto = (n.get("protocol") or "").lower()
            if proto not in SUPPORTED:
                skipped.append((n.get("remarks"), proto))
                continue
            info = parse_endpoint(n)
            key = (info["server"], info["port"])
            if key in seen:
                continue
            seen.add(key)
            info["lane"] = lane
            infos.append(info)

    if not infos:
        print("[x] 没有可用节点")
        return 1

    print(f"[+] 可用 {len(infos)} 个节点，跳过 {len(skipped)} 个不支持的协议"
          f"（{', '.join(sorted({p for _, p in skipped}))}）")
    for i in infos:
        print(f"    {i['name']:<20} {i['protocol']:<12} {i['server']}:{i['port']}")

    # ---- 2. Clash：官方骨架 + 自建 proxies ----
    origin_text = fetch_sub_yaml(sub_uuid, 1) or fetch_sub_yaml(sub_uuid, 2)
    names = [i["name"] for i in infos]
    if origin_text:
        try:
            cfg = yaml.safe_load(origin_text)
        except Exception:
            cfg = {}
    else:
        cfg = {}

    clash = dict(cfg) if cfg else {}
    clash["proxies"] = [p for p in (clash_proxy(i) for i in infos) if p]
    # 官方 374 条规则全部引用 QIANLI / 自动选择 / 故障转移，组名必须保持一致
    clash["proxy-groups"] = [
        {"name": "QIANLI", "type": "select", "proxies": names},
        {"name": "自动选择", "type": "url-test",
         "url": "http://www.gstatic.com/generate_204",
         "interval": 300, "tolerance": 50, "proxies": names},
        {"name": "故障转移", "type": "fallback",
         "url": "http://www.gstatic.com/generate_204",
         "interval": 300, "proxies": names},
    ]
    if not clash.get("rules"):
        clash.update({
            "mixed-port": 7890, "allow-lan": False, "mode": "rule",
            "log-level": "info", "dns": {"enable": True, "ipv6": False,
                                         "enhanced-mode": "fake-ip",
                                         "nameserver": ["223.5.5.5", "119.29.29.29"]},
            "rules": ["GEOIP,CN,DIRECT", "MATCH,QIANLI"],
        })

    with open("jidian_clash.yaml", "w") as f:
        f.write("# 极点加速器（jidianvpn.com）订阅，规则沿用官方配置\n")
        yaml.safe_dump(clash, f, allow_unicode=True, sort_keys=False, width=4096)

    # ---- 3. sing-box ----
    tags, obs = [], []
    for i, info in enumerate(infos):
        tag = f"jidian-{i+1}"
        obs.append(sb_outbound(info, tag))
        tags.append(tag)
    singbox = {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "remote", "type": "https", "server": "1.1.1.1",
                 "server_port": 443, "path": "/dns-query", "detour": "proxy"},
                {"tag": "local", "type": "local"},
            ],
            "rules": [{"ip_is_private": True, "server": "local"}],
            "final": "remote", "strategy": "ipv4_only",
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
        "route": {"auto_detect_interface": True,
                  "rules": [{"action": "sniff"},
                            {"protocol": "dns", "action": "hijack-dns"},
                            {"ip_is_private": True, "outbound": "direct"}],
                  "final": "proxy"},
    }
    with open("jidian_singbox.json", "w") as f:
        json.dump(singbox, f, ensure_ascii=False, indent=2)

    # ---- 4. 链接 ----
    links = [x for x in (to_link(i) for i in infos) if x]
    with open("jidian_sub.txt", "w") as f:
        f.write("\n".join(links) + "\n")
    with open("jidian_sub_b64.txt", "w") as f:
        f.write(base64.b64encode("\n".join(links).encode()).decode() + "\n")

    # ---- 5. 元数据 ----
    with open("jidian_nodes.json", "w") as f:
        json.dump({
            "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "sub_uuid": sub_uuid, "subject": subject,
            "count": len(infos),
            "skipped_anyconnect": [{"name": n, "protocol": p} for n, p in skipped],
            "nodes": [{"name": i["name"], "lane": i["lane"], "protocol": i["protocol"],
                       "server": i["server"], "port": i["port"], "sni": i["sni"],
                       "method": i["method"], "speed_limit_mbps": i["speed_limit"],
                       "load_percent": round(i["load"], 1) if isinstance(i["load"], (int, float)) else None}
                      for i in infos],
        }, f, ensure_ascii=False, indent=2)

    print(f"[√] 生成 {len(infos)} 个节点：jidian_clash.yaml / jidian_singbox.json / "
          f"jidian_sub.txt / jidian_sub_b64.txt / jidian_nodes.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
