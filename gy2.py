#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""光影VPN 新版节点抓取: di:设备ID 自动注册 -> getserver -> 解出节点链接"""
import base64, json, os, sys, uuid
import requests
from Crypto.Cipher import AES

BASE = "https://www.gynew.men/api/"
KEY = b"Gz#8kP@mQ2xL!nRv4Yw&TbE6sJdF0cAh"
IV = b"Xk3N7pQ1mZ9wL5rT"
H = {"agentX": "super-ok-http", "User-Agent": "okhttp/4.9.0"}
OUT = os.environ.get("GY_OUT", "guangying.txt")


def dec(s):
    try:
        pt = AES.new(KEY, AES.MODE_CBC, IV).decrypt(base64.b64decode(s.strip()))
        return pt[:-pt[-1]].decode("utf-8", "replace")
    except Exception:
        return None


def call(ep, data):
    r = requests.post(BASE + ep, data=data, headers=H, timeout=15)
    return dec(r.text) or r.text


def main():
    link = None
    for attempt in range(6):
        dev = "di:" + uuid.uuid4().hex[:16]
        p = {"imei": dev, "user": "0", "v": "3.2.1", "cid": "1",
             "a": "13", "b": "google", "c": "Pixel 7", "d": "redfin"}
        info = call("user/getInfo", p)
        print(f"[{attempt + 1}] {dev} -> {info[:80]}")
        if "登录成功" not in info:
            continue
        srv = call("user/getserver", p)
        print("    getserver:", srv[:80])
        try:
            d = json.loads(srv)
        except Exception:
            continue
        if d.get("link"):
            link = d["link"]
            print("    link len:", len(link))
            break
    if not link:
        print("[x] 没有拿到 link")
        return 1

    pt = dec(link)
    print("\n=== link 明文 ===")
    print((pt or link)[:3000])

    if pt and ("ss://" in pt or "vless://" in pt or "trojan://" in pt):
        lines = [l.strip() for l in pt.replace("\\n", "\n").splitlines() if l.strip()]
        # 也尝试从 JSON 里取
        if len(lines) == 1 and "://" not in lines[0]:
            try:
                j = json.loads(pt)
                for k in ("url", "link", "config", "data"):
                    if isinstance(j.get(k), str):
                        lines = [x.strip() for x in j[k].splitlines() if x.strip()]
            except Exception:
                pass
        nodes = [l for l in lines if "://" in l]
        if nodes:
            body = "\n".join(nodes).encode()
            open(OUT, "wb").write(base64.b64encode(body))
            print(f"\n[+] 写入 {OUT}: {len(nodes)} 节点")
            for n in nodes[:5]:
                print("    ", n[:90])
    return 0


if __name__ == "__main__":
    sys.exit(main())
