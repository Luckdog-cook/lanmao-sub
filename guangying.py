#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
光影VPN (com.guangying.go 3.2.1) 节点抓取
------------------------------------------
老版 43.159.7.5 的 SS 已停服(全端口扫描只剩 22), 新版改走 API:

  BASE  https://www.gynew.men/api/
  HDR   agentX: super-ok-http
  加密  AES-256-CBC  key=Gz#8kP@mQ2xL!nRv4Yw&TbE6sJdF0cAh  iv=Xk3N7pQ1mZ9wL5rT

流程:
  getInfo(imei=di:<16hex uuid>)  首次自动注册, 返回 user id
  getserver                      返回 {"ret":2,"link":"<sing-box JSON 明文>"}
  link 是 vless + reality + vision 节点, 直接转 vless:// URI

注意:
  - imei 必须是 "di:" + 16 位 hex, 纯 32 位 hex 会被拒
  - 同一出口 IP 注册 2~3 次后服务端开始返回"注册失败", 需换 IP
"""
import base64, json, os, sys, uuid
import requests
from urllib.parse import quote

BASE = "https://www.gynew.men/api/"
KEY = b"Gz#8kP@mQ2xL!nRv4Yw&TbE6sJdF0cAh"
IV = b"Xk3N7pQ1mZ9wL5rT"
H = {"agentX": "super-ok-http", "User-Agent": "okhttp/4.9.0"}
OUT = os.environ.get("GY_OUT", "guangying.txt")
TRIES = int(os.environ.get("GY_TRIES", "8"))
DEVICES = [("13", "google", "Pixel 7", "redfin"),
           ("12", "samsung", "SM-G998B", "o1s"),
           ("11", "Xiaomi", "M2012K11AC", "venus"),
           ("10", "HUAWEI", "ELS-AN00", "HWELE")]


def dec(s):
    """响应是 AES-256-CBC + base64; 解不开说明是明文/HTML"""
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


def main():
    nodes, seen = [], set()
    for i in range(TRIES):
        a, b, c, d = DEVICES[i % len(DEVICES)]
        dev = "di:" + uuid.uuid4().hex[:16]
        p = {"imei": dev, "user": "0", "v": "3.2.1", "cid": "1",
             "a": a, "b": b, "c": c, "d": d}
        info = call("user/getInfo", p)
        if "登录成功" not in (info or ""):
            print(f"[{i+1}] {dev} 注册失败: {(info or '')[:60]}")
            continue
        uid = ""
        try:
            uid = json.loads(info).get("user", "")
        except Exception:
            pass
        # 先试 getlist: 可能一次返回全部节点
        gl = call("user/getlist", p)
        print(f"    getlist: {(gl or '')[:200]}")
        srv = call("user/getserver", p)
        try:
            j = json.loads(srv)
        except Exception:
            print(f"[{i+1}] {dev} user={uid} getserver 异常")
            continue
        link = j.get("link")
        if not link:
            print(f"[{i+1}] {dev} user={uid} 无 link: {str(j)[:80]}")
            continue
        try:
            n = json.loads(link) if link.strip().startswith("{") else json.loads(dec(link) or "{}")
        except Exception:
            print(f"[{i+1}] link 解析失败: {link[:80]}")
            continue
        key = (n.get("server"), n.get("server_port"), n.get("uuid"))
        print(f"[{i+1}] {dev} user={uid} -> {n.get('server')}:{n.get('server_port')} "
              f"{'NEW' if key not in seen else 'dup'}")
        if key in seen:
            continue
        seen.add(key)
        n["_tag"] = f"光影-{n.get('server')}"
        nodes.append(n)

    if not nodes:
        print("[x] 没有抓到节点, 保留旧文件")
        return 1

    uris = [to_uri(n) + "#" + quote(n["_tag"]) for n in nodes]
    open(OUT, "wb").write(base64.b64encode("\n".join(uris).encode()))
    print(f"\n[+] {OUT}: {len(nodes)} 个节点")
    for u in uris:
        print("   ", u[:110])
    return 0


if __name__ == "__main__":
    sys.exit(main())
