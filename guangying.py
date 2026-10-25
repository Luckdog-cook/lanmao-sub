#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
光影VPN (com.guangying.go 3.2.1) 全节点抓取
--------------------------------------------
老版 43.159.7.5 的 SS 已停服(全端口只剩 22), 新版走 API:

  BASE  https://www.gynew.men/api/
  HDR   agentX: super-ok-http
  加密  AES-256-CBC  key=Gz#8kP@mQ2xL!nRv4Yw&TbE6sJdF0cAh  iv=Xk3N7pQ1mZ9wL5rT

流程:
  1. getInfo(imei="di:"+16hex)   设备自动注册, 返回 user id
  2. getlist(user=<id>)          返回全部线路分组 + server id + 地区
  3. getserver(user=<id>,id=<sid>) 逐个取配置 -> link 是 sing-box JSON 明文
  4. 转 vless:// URI -> base64 订阅

注意:
  - imei 必须是 "di:" + 16 位 hex
  - 必须先拿到 user id 再调 getlist, 传 user=0 会返回 ThinkPHP 错误页
  - VIP 组用参数 id, SVIP 组用 server_id, 脚本两种都试
"""
import base64, json, os, sys, uuid
import requests
from urllib.parse import quote

BASE = "https://www.gynew.men/api/"
KEY = b"Gz#8kP@mQ2xL!nRv4Yw&TbE6sJdF0cAh"
IV = b"Xk3N7pQ1mZ9wL5rT"
H = {"agentX": "super-ok-http", "User-Agent": "okhttp/4.9.0"}
OUT = os.environ.get("GY_OUT", "guangying.txt")
TRIES = int(os.environ.get("GY_TRIES", "6"))


def dec(s):
    try:
        from Crypto.Cipher import AES as _A
        raw = base64.b64decode(s.strip().replace("\\/", "/"))
        pt = _A.new(KEY, _A.MODE_CBC, IV).decrypt(raw)
        return pt[:-pt[-1]].decode("utf-8", "replace")
    except Exception:
        return None


def call(ep, data):
    try:
        r = requests.post(BASE + ep, data=data, headers=H, timeout=15)
        return dec(r.text) or r.text
    except Exception as e:
        return f"ERR {e}"


def to_uri(n):
    tls = n.get("tls") or {}
    r = tls.get("reality") or {}
    q = {
        "encryption": "none",
        "security": "reality" if r.get("enabled") else "tls",
        "sni": tls.get("server_name", ""),
        "fp": (tls.get("utls") or {}).get("fingerprint", "chrome"),
        "type": n.get("network", "tcp"),
    }
    if n.get("flow"):
        q["flow"] = n["flow"]
    if r.get("enabled"):
        q["pbk"] = r.get("public_key", "")
        q["sid"] = r.get("short_id", "")
    if n.get("network") == "ws":
        q["path"] = (n.get("ws_settings") or {}).get("path", "/")
    qs = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in q.items() if v)
    return f'vless://{n["uuid"]}@{n["server"]}:{n["server_port"]}?{qs}'


def register():
    """设备自动注册, 返回 (params, uid)"""
    for i in range(TRIES):
        dev = "di:" + uuid.uuid4().hex[:16]
        p = {"imei": dev, "user": "0", "v": "3.2.1", "cid": "1",
             "a": "13", "b": "google", "c": "Pixel 7", "d": "redfin"}
        info = call("user/getInfo", p)
        if "登录成功" in (info or ""):
            try:
                uid = json.loads(info)["user"]
            except Exception:
                uid = "0"
            return {**p, "user": uid}, uid
        print(f"[{i+1}] {dev} 注册失败: {(info or '')[:60]}")
    return None, None


def main():
    p, uid = register()
    if not p:
        print("[x] 注册失败(该 IP 额度用尽), 保留旧文件")
        return 1
    print(f"[+] 注册成功 user={uid}")

    gl = call("user/getlist", p)
    try:
        groups = json.loads(gl)["group"]
    except Exception:
        print("[x] getlist 失败:", (gl or "")[:120])
        return 1

    nodes = []
    for g in groups:
        gname = g.get("name", "")
        for s in g.get("server", []):
            sid = s.get("id")
            loc = (s.get("location") or "").strip()
            link = None
            for key in ("id", "server_id", "serverId"):
                r = call("user/getserver", {**p, key: str(sid)})
                try:
                    j = json.loads(r)
                except Exception:
                    continue
                if j.get("link"):
                    link = j["link"]
                    break
            if not link:
                print(f"    {gname} / {loc} (id={sid}) 失败")
                continue
            try:
                n = json.loads(link) if link.strip().startswith("{") else json.loads(dec(link) or "{}")
            except Exception:
                print(f"    {gname} / {loc} link 解析失败")
                continue
            n["_tag"] = loc or f"{gname}-{sid}"
            nodes.append(n)
            print(f"    {gname} / {loc:<12} {n.get('server')}:{n.get('server_port')}")

    if not nodes:
        print("[x] 没有节点")
        return 1

    uris = [to_uri(n) + "#" + quote(n["_tag"]) for n in nodes]
    open(OUT, "wb").write(base64.b64encode("\n".join(uris).encode()))
    print(f"\n[+] {OUT}: {len(nodes)} 个节点")
    return 0


if __name__ == "__main__":
    sys.exit(main())
