#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
跨境VPN（kuajingkeji.com / 极光 VPN）节点抓取

逆向自官方 Android App v3.4.3（包名 com.free.aurora.vpn，sing-box 内核）：
  1. 设备号 + 时间戳 派生 HMAC 密钥，对 METHOD|path|body|ts|deviceId 签名
  2. 注册即送 1 天 PLATINUM（vipTrialDays=1）
  3. /app/vss/lss/allocate 按国家分配节点，返回 AES/CTR 加密的 vless 链接
  4. 用固定 SALT 的 SHA256 作为 AES-256 key 解密

用法：
  python kuajing_nodes.py                 # 自动注册 + 拉全部国家
  python kuajing_nodes.py --countries HK,JP,SG
  python kuajing_nodes.py --reuse         # 复用 account.json 里的账号
  python kuajing_nodes.py --check         # 额外做 TCP 存活探测

产出：kuajing_nodes.txt / kuajing_nodes.base64 / kuajing_account.json
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import random
import socket
import ssl
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

try:
    from Crypto.Cipher import AES
except ImportError:
    sys.exit("缺少依赖：pip install pycryptodome")

# ---------- 逆向得到的常量（来自官方 App） ----------
SALT = "K9mN7pQ2vX8bE4wR6jL3nA5sD9gH2kP7uY1tI6oE8rQ4mN9vX3bK7sA2wE5gL8pU"
TIME_WINDOW = 180000                      # 3 分钟一个签名窗口
UA = "free-bird/3.4.3 (Android)"          # 关键：服务端按 UA 分流，写错就是 409
HOSTS = ["https://jiguang666.top/api", "https://jiguang888.top/api"]
CTX = ssl._create_unverified_context()

OUT_TXT = "kuajing_nodes.txt"
OUT_B64 = "kuajing_nodes.base64"
ACC_FILE = "kuajing_account.json"


def sha_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def derive_key(ts: int, dev: str) -> str:
    inner = sha_hex(SALT + sha_hex(dev[:40]))
    return sha_hex("|".join([inner, str(ts // TIME_WINDOW), dev]))


def sign(method: str, path: str, body: str, ts: int, dev: str) -> str:
    data = "|".join([method.upper(), path, body, str(ts), dev])
    raw = hmac.new(derive_key(ts, dev).encode(), data.encode(), hashlib.sha256).digest()
    return base64.b64encode(raw).decode()


def api(path, body=None, token=None, dev=None, method=None, timeout=20):
    dev = dev or uuid.uuid4().hex
    ts = int(time.time() * 1000)
    bs = json.dumps(body, separators=(",", ":"), ensure_ascii=False) if body is not None else ""
    m = method or ("POST" if body is not None else "GET")
    headers = {
        "User-Agent": UA,
        "Accept": "application/json",
        "X-Timestamp": str(ts),
        "X-Device-Id": dev,
        "X-Signature": sign(m, path, bs, ts, dev),
    }
    if body is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token

    err = None
    for base in HOSTS:
        try:
            req = urllib.request.Request(
                base + path, data=bs.encode() if bs else None, headers=headers, method=m
            )
            with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            try:
                return json.loads(e.read().decode())
            except Exception:
                err = f"HTTP {e.code}"
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
    return {"_error": err}


def aes_key() -> bytes:
    return bytes.fromhex(sha_hex(SALT))


def decrypt_cfg(enc_json: str) -> str:
    """vpnConfigEncrypted -> 明文 vless 链接"""
    e = json.loads(enc_json)
    iv = base64.b64decode(e["iv"])
    ct = base64.b64decode(e["ciphertext"])
    cipher = AES.new(aes_key(), AES.MODE_CTR, nonce=b"",
                     initial_value=int.from_bytes(iv, "big"))
    return cipher.decrypt(ct).decode("utf-8", "replace")


def rand_account():
    u = "kj" + "".join(random.choices(string.digits, k=8))
    p = "Aa" + "".join(random.choices(string.digits, k=8))
    return u, p


def load_account():
    if not os.path.exists(ACC_FILE):
        return None
    try:
        d = json.load(open(ACC_FILE))
        if d.get("username") and d.get("password"):
            return d
    except Exception:
        pass
    return None


def save_account(d):
    with open(ACC_FILE, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=2)


def login_or_register(reuse: bool):
    acc = load_account() if reuse else None
    if acc:
        r = api("/app/users/login", {
            "username": acc["username"], "password": acc["password"],
            "deviceId": acc["deviceId"], "platform": "ANDROID",
        }, dev=acc["deviceId"])
        if r.get("token"):
            print(f"复用账号 {acc['username']}  VIP={((r.get('data') or {}).get('vipType'))}")
            return acc["username"], acc["password"], acc["deviceId"], r["token"], r.get("data") or {}

    dev = uuid.uuid4().hex
    u, p = rand_account()
    reg = api("/app/users/register", {
        "username": u, "password": p, "deviceId": dev, "platform": "ANDROID",
    }, dev=dev)
    if not (reg.get("data") or reg.get("status") == 0):
        print("注册失败:", json.dumps(reg, ensure_ascii=False)[:200])
        return None

    lr = api("/app/users/login", {
        "username": u, "password": p, "deviceId": dev, "platform": "ANDROID",
    }, dev=dev)
    tok = lr.get("token")
    data = lr.get("data") or {}
    print(f"注册新账号 {u} / {p}  VIP={data.get('vipType')} 到期={data.get('vipExpireTime')}")
    save_account({"username": u, "password": p, "deviceId": dev, "token": tok,
                  "vipType": data.get("vipType"), "vipExpireTime": data.get("vipExpireTime")})
    return u, p, dev, tok, data


def tcp_alive(host, port, timeout=4.0):
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--countries", default="", help="逗号分隔的国家码，默认全部")
    ap.add_argument("--reuse", action="store_true", help="复用 kuajing_account.json 里的账号")
    ap.add_argument("--line-type", default="NORMAL", choices=["NORMAL", "DEDICATED"])
    ap.add_argument("--check", action="store_true", help="额外做 TCP 存活探测")
    ap.add_argument("--tries", type=int, default=2, help="每个国家分配次数（可榨出不同服务器）")
    ap.add_argument("--interval", type=float, default=1.8, help="分配间隔秒")
    ap.add_argument("--out-dir", default=".")
    args = ap.parse_args()

    got = login_or_register(args.reuse)
    if not got:
        sys.exit(1)
    user, pwd, dev, token, info = got

    countries = api("/app/countries/active", token=token, dev=dev)
    clist = countries.get("data") or []
    if not clist:
        print("国家列表为空:", json.dumps(countries, ensure_ascii=False)[:200])
        sys.exit(1)

    want = {c.strip().upper() for c in args.countries.split(",") if c.strip()}
    if want:
        clist = [c for c in clist if (c.get("code") or "").upper() in want]

    print(f"国家数: {len(clist)}  线路: {args.line_type}  每国尝试 {args.tries} 次")
    links, detail = [], []
    seen_keys = set()

    def allocate(code):
        return api("/app/vss/lss/allocate",
                   {"countryCode": code, "lineType": args.line_type, "deviceCode": dev},
                   token=token, dev=dev)

    for c in clist:
        code = (c.get("code") or "").upper()
        name = c.get("name") or code
        ok = 0
        last_msg = ""
        for attempt in range(max(1, args.tries)):
            r = allocate(code)
            if r.get("_error") and "频繁" in str(r.get("_error")):
                time.sleep(5)
                r = allocate(code)
            d = r.get("data") or {}
            enc = d.get("vpnConfigEncrypted")
            if not enc:
                last_msg = r.get("message") or r.get("_error") or "无数据"
                break
            try:
                link = decrypt_cfg(enc)
            except Exception as e:
                last_msg = f"解密失败 {type(e).__name__}"
                break
            u = urllib.parse.urlparse(link)
            port = u.port or 443
            key = (u.hostname, u.username, port)
            if key in seen_keys:
                time.sleep(args.interval)
                continue
            if args.check and not tcp_alive(u.hostname, port):
                last_msg = f"{u.hostname}:{port} 不通"
                time.sleep(args.interval)
                continue
            seen_keys.add(key)
            frag = urllib.parse.unquote(u.fragment or "")
            link = f"{link.split('#')[0]}#{urllib.parse.quote(f'{code}-{frag}')}"
            links.append(link)
            detail.append({"country": code, "name": name, "nodeId": d.get("nodeId"),
                           "leaseId": d.get("leaseId"), "host": u.hostname, "port": port,
                           "protocol": d.get("protocolType")})
            ok += 1
            print(f"  {code:4s} {name:8s} ✓ {d.get('protocolType')} {u.hostname}:{port} (nodeId={d.get('nodeId')})")
            time.sleep(args.interval)
        if ok == 0:
            print(f"  {code:4s} {name:8s} ✗ {last_msg}")

    if not links:
        print("\n未获取到任何节点，保留旧文件不覆盖")
        sys.exit(1)

    os.makedirs(args.out_dir, exist_ok=True)
    txt = "\n".join(links) + "\n"
    open(os.path.join(args.out_dir, OUT_TXT), "w", encoding="utf-8").write(txt)
    open(os.path.join(args.out_dir, OUT_B64), "w", encoding="utf-8").write(
        base64.b64encode(txt.encode()).decode())
    print(f"\n节点: {len(links)}  -> {OUT_TXT} / {OUT_B64}")
    print(f"账号: {user} / {pwd}  VIP={info.get('vipType')} 到期={info.get('vipExpireTime')}")


if __name__ == "__main__":
    main()
