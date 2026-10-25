#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""光影新版 API 探测: 设备自动注册 + 节点下发"""
import base64, json, uuid, sys
import requests
from Crypto.Cipher import AES

BASE = "https://www.gynew.men/api/"
KEY = b"Gz#8kP@mQ2xL!nRv4Yw&TbE6sJdF0cAh"
IV = b"Xk3N7pQ1mZ9wL5rT"
H = {"agentX": "super-ok-http", "User-Agent": "okhttp/4.9.0"}


def dec(s: str) -> str:
    try:
        ct = base64.b64decode(s.strip())
        pt = AES.new(KEY, AES.MODE_CBC, IV).decrypt(ct)
        return pt[:-pt[-1]].decode("utf-8", "replace")
    except Exception:
        return s[:200]


def call(ep: str, data: dict):
    try:
        r = requests.post(BASE + ep, data=data, headers=H, timeout=15)
        return dec(r.text)
    except Exception as e:
        return f"ERR {e}"


def main():
    dev = uuid.uuid4().hex
    print("imei:", dev)
    base = {"imei": dev, "v": "3.2.1", "cid": "1",
            "a": "13", "b": "google", "c": "Pixel 7", "d": "redfin"}

    print("\n[1] getInfo (启动页首注册)")
    print("   ", call("user/getInfo", {**base, "user": "0"})[:200])

    print("\n[2] getserver 各种 user 值")
    for u in ["0", "1", "-1", ""]:
        print(f"   user={u!r}: {call('user/getserver', {**base, 'user': u})[:200]}")

    print("\n[3] login new=<imei>")
    print("   ", call("user/login", {"new": dev, "imei": dev, "v": "3.2.1",
                                     "cid": "1", "user": "0"})[:200])

    print("\n[4] getlist")
    print("   ", call("user/getlist", {**base, "user": "0"})[:200])


if __name__ == "__main__":
    main()
