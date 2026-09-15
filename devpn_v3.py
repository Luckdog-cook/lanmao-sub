#!/usr/bin/env python3
"""DeVPN 节点拉取工具 v3 - 完整激活版（单文件，零依赖）

v3 相对 v2 的核心修复（2026-08-12 实测打通）：
================================================
此前脚本拉取的节点全部无法连接，App 连接后同节点却可用。原因：
App 拉取节点后，还会对每个节点调用一次激活接口：

    POST https://{domainName}:443/server/setAccount
    body = {"data": sm2ciphertext}     # 节点响应里的一次性授权码
    响应 {"statusCode":201,"data":true} 的节点才被服务端授权，之后用明文 uuid 才能连。

关键约束（实测确认）：
1. 拉节点请求必须带完整的设备证明头（dsf-token + dsfunique + fingerprint + requestid），
   裸 token 请求拉到的节点即使调用 setAccount 也无法激活。
2. setAccount 必须使用与拉取请求相同的 requestid（proof）。
   跨请求重新生成 proof 会导致 data:false（设备证明与拉取会话绑定）。
   因此本脚本在单次运行内复用同一份请求头，拉取后立即激活。
3. sm2ciphertext 是一次性的：App 用过的 sm2ciphertext 再提交返回 data:false。

本文件为单文件实现：SM3 / SM2-encrypt(dsfunique) / nativeBuildProof(make_proof)
全部内嵌，仅依赖 Python 标准库，可在任意机器（Windows/macOS/Linux/Termux）直接运行。

用法：
    python devpn_v3.py                    # 交互式选择国家拉取+激活
    python devpn_v3.py --no-activate      # 只拉取不激活（调试用）
    python devpn_v3.py --code HK,JP --target 5   # 非交互：指定国家+目标数量
"""
import argparse
import base64
import hashlib
import json
import os
import random
import ssl
import sys
import time
import urllib.request
import urllib.error

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ================================================================
# 内嵌：SM3 + SM2 加密（dsfunique，从 Hermes 字节码逆向，C1C3C2）
# ================================================================
_SM3_IV = bytes.fromhex("7380166f4914b2b9172442d7da8a0600a96f30bc163138aae38dee4db0fb0e4e")

def _rotl(x, n):
    n %= 32
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def sm3(msg: bytes) -> bytes:
    """标准 SM3，返回 32 字节。"""
    ml = len(msg) * 8
    msg = msg + b"\x80"
    while len(msg) % 64 != 56:
        msg += b"\x00"
    msg += ml.to_bytes(8, "big")
    v = [int.from_bytes(_SM3_IV[j:j + 4], "big") for j in range(0, 32, 4)]
    for i in range(0, len(msg), 64):
        block = msg[i:i + 64]
        w = list(int.from_bytes(block[j:j + 4], "big") for j in range(0, 64, 4))
        for j in range(16, 68):
            x = w[j - 16] ^ w[j - 9] ^ _rotl(w[j - 3], 15)
            w.append((x ^ _rotl(x, 15) ^ _rotl(x, 23)) ^ _rotl(w[j - 13], 7) ^ w[j - 6])
        wp = [w[j] ^ w[j + 4] for j in range(64)]
        a, b, c, d, e, f, g, h = v
        for j in range(64):
            if j < 16:
                t = 0x79CC4519
                ff = a ^ b ^ c
                gg = e ^ f ^ g
            else:
                t = 0x7A879D8A
                ff = (a & b) | (a & c) | (b & c)
                gg = (e & f) | ((~e & 0xFFFFFFFF) & g)
            ss1 = _rotl((_rotl(a, 12) + e + _rotl(t, j)) & 0xFFFFFFFF, 7)
            ss2 = ss1 ^ _rotl(a, 12)
            tt1 = (ff + d + ss2 + wp[j]) & 0xFFFFFFFF
            tt2 = (gg + h + ss1 + w[j]) & 0xFFFFFFFF
            d = c
            c = _rotl(b, 9)
            b = a
            a = tt1
            h = g
            g = _rotl(f, 19)
            f = e
            e = (tt2 ^ _rotl(tt2, 9) ^ _rotl(tt2, 17)) & 0xFFFFFFFF
        v = [x ^ y for x, y in zip(v, [a, b, c, d, e, f, g, h])]
    return b"".join(x.to_bytes(4, "big") for x in v)

# SM2 曲线参数 (sm2p256v1)
_P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
_A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
_B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
_N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
_GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
_GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
# App 内嵌的 SM2 公钥(04 前缀 + 64 字节) —— dsfunique 加密用
_PUBKEY_HEX = ("04d882d23c6d01534de563f8b10539ac32edf1a4c986ca59044567b86d6c652b2d"
               "34483ba97f9ea3c0950f36697ea858c966af56cc8682c83b83f57c843823aeff")
_PX = int(_PUBKEY_HEX[2:66], 16)
_PY = int(_PUBKEY_HEX[66:130], 16)

def _inv(x):
    return pow(x, _P - 2, _P)

def _point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + _A) * _inv(2 * y1) % _P
    else:
        lam = (y2 - y1) * _inv(x2 - x1) % _P
    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return (x3, y3)

def _scalar_mul(k, pt):
    k = k % _N
    r = None
    while k:
        if k & 1:
            r = _point_add(r, pt)
        pt = _point_add(pt, pt)
        k >>= 1
    return r

def _kdf(z: bytes, klen: int) -> bytes:
    ct = 1
    out = b""
    while len(out) < klen:
        out += sm3(z + ct.to_bytes(4, "big"))
        ct += 1
    return out[:klen]

def _sm2_encrypt(msg: bytes) -> bytes:
    """C1C3C2，C1 不带 0x04 前缀。返回原始字节。"""
    g = (_GX, _GY)
    p = (_PX, _PY)
    while True:
        k = random.randrange(1, _N)
        c1 = _scalar_mul(k, g)
        s = _scalar_mul(k, p)
        x2 = s[0].to_bytes(32, "big")
        y2 = s[1].to_bytes(32, "big")
        t = _kdf(x2 + y2, len(msg))
        if any(t):
            break
    c2 = bytes(a ^ b for a, b in zip(msg, t))
    c3 = sm3(x2 + msg + y2)
    return c1[0].to_bytes(32, "big") + c1[1].to_bytes(32, "big") + c3 + c2

def dsfunique_for(device_id: str) -> str:
    """device_id(16hex 字符串) → dsfunique 224-hex。"""
    return _sm2_encrypt(device_id.encode("ascii")).hex()

# ================================================================
# 内嵌：nativeBuildProof（make_proof，已用 hook ground truth 验证）
# ================================================================
MAGIC = "DVP2NID2026"
PKG = "com.desafa.devpn"
SIGN = ("CA:43:9D:8D:87:EB:ED:AD:FC:71:E1:DF:70:6B:54:D0:"
        "8B:46:6C:13:A2:2A:9C:D3:1E:20:88:1A:96:07:2F:00")
APP_VER = "2.1.17"

def make_proof(android_id, ts_ms, urandom_nonce):
    """nativeBuildProof 完整算法。"""
    key = hashlib.sha256(f"{PKG}|{SIGN}|{urandom_nonce}|{MAGIC}".encode()).digest()
    xor = bytes(a ^ k for a, k in zip(android_id.encode(), key[:16]))
    device_cipher = xor.hex()
    proof = hashlib.sha256(
        f"{device_cipher}|{PKG}|{SIGN}|{ts_ms}|{urandom_nonce}|{MAGIC}".encode()
    ).hexdigest()
    return {
        "version": 1,
        "packageName": PKG,
        "timestamp": ts_ms,
        "nonce": urandom_nonce,
        "deviceCipher": device_cipher,
        "proof": proof,
    }

# ================================================================
# 配置
# ================================================================
DEFAULT_TOKEN = "dsf-token"
OWNER_ID = "f53dbff288fc5090"
WS_PATH = "/ws-vmess"
DOMAINS = [
    "https://mpn.desafa.net",
    "https://news.devpn.vip",
    "https://book.devpn.vip",
    "https://abs.devpn.vip",
    "https://sports.devpn.vip",
]

_HERE = os.path.dirname(os.path.abspath(__file__))
if sys.platform.startswith("linux") and os.path.exists("/storage/emulated/0"):
    SAVE_DIR = "/storage/emulated/0/Download/"          # Android (Termux)
elif sys.platform == "win32":
    SAVE_DIR = os.path.join(os.path.expanduser("~"), "Downloads")
else:
    SAVE_DIR = _HERE

# 节点服务器是自签/非标准证书，关闭校验（与 App vpnBypassPost 行为一致）
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

# ================================================================
# 设备证明头（一次生成，全程复用同一份 requestid）
# ================================================================
def make_headers(token, device_id):
    device = {
        "brand": "motorola",
        "deviceId": device_id,
        "systemName": "Android",
        "isTablet": "false",
        "deviceName": "motorola edge X30",
        "deviceModel": "XT2201-2",
        "osVersion": "14",
        "appVersion": APP_VER,
        "platform": "android",
    }
    fingerprint = hashlib.sha256(
        json.dumps(device, separators=(",", ":")).encode()
    ).hexdigest()
    dsfunique = dsfunique_for(device_id)
    ts_ms = str(int(time.time() * 1000))
    urandom_nonce = os.urandom(16).hex()
    proof = make_proof(device_id, ts_ms, urandom_nonce)
    return {
        "dsf-token": token,
        "Language": "zh_HK",
        "x-version": APP_VER,
        "fingerprint": fingerprint,
        "manufacturer": "motorola",
        "platform": "android",
        "devicemodel": "XT2201-2",
        "osversion": "14",
        "appversion": APP_VER,
        "devicename": "motorola edge X30",
        "dsfunique": dsfunique,
        "requestid": json.dumps(proof, separators=(",", ":")),
    }

# ================================================================
# API
# ================================================================
def http(method, url, headers=None, body=None, timeout=20):
    req = urllib.request.Request(url, method=method, headers=headers or {})
    if body is not None:
        req.add_header("Content-Type", "application/json")
        if isinstance(body, (dict, list)):
            req.data = json.dumps(body).encode()
        else:
            req.data = body.encode()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return -1, str(e)

def fetch_nodes(base, token, hdrs, code, residence=False):
    path = "/app/equipment/with-account-home-v1" if residence else "/app/devpn/unified-with-account"
    st, body = http("POST", f"{base}/api/dsf{path}?code={code}&uuid={OWNER_ID}", hdrs, body=[])
    try:
        return json.loads(body)
    except Exception:
        return {"code": -1, "msg": "bad response"}

def get_countries(base, token, hdrs, residence=False):
    if residence:
        st, body = http("GET", f"{base}/api/dsf/app/equipment/list-home?language=zh_HK", hdrs)
    else:
        st, body = http("GET",
                        f"{base}/api/dsf/app/devpn/country-list?ownerId={OWNER_ID}&language=zh_HK&variant=0",
                        hdrs)
    try:
        return json.loads(body).get("data") or []
    except Exception:
        return []

def activate_node(node):
    """POST sm2ciphertext 到节点服务器的 /server/setAccount。
    返回 True 表示激活成功（data:true）。"""
    domain = node.get("domainName")
    port = node.get("appPort") or "443"
    sm2 = node.get("sm2ciphertext") or ""
    url = f"https://{domain}:{port}/server/setAccount"
    st, body = http("POST", url, {"Content-Type": "application/json"}, body={"data": sm2})
    try:
        return json.loads(body).get("data") is True
    except Exception:
        return False

# ================================================================
# vmess
# ================================================================
def vmess_link(node, name):
    domain = node.get("domainName")
    cfg = {
        "v": "2", "ps": name,
        "add": domain,
        "port": str(node.get("appPort") or "443"),
        "id": node["uuid"], "aid": "0", "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": domain,
        "path": WS_PATH,
        "tls": "tls",
        "sni": domain,
    }
    return "vmess://" + base64.b64encode(json.dumps(cfg).encode()).decode()

# ================================================================
# 交互
# ================================================================
def select_countries(base, token, hdrs, residence):
    countries = get_countries(base, token, hdrs, residence)
    if not countries:
        print("❌ 获取国家列表失败或为空（可能 token 已失效）")
        sys.exit(1)
    if len(countries) <= 10:
        print(f"⚠ 国家列表只有 {len(countries)} 个（疑似免费/新账号视图，非 token 失效）")
        print(f"   当前使用的 token: {token}")
    print("\n可选国家：")
    for idx, c in enumerate(countries, 1):
        print(f"{idx:2}. {c.get('egName')} - {c.get('name')} ({c.get('total', 0)}个节点)")
    while True:
        sel = input("请选择序号（多个用逗号分隔）: ").strip()
        if not sel:
            return []
        try:
            indices = [int(x.strip()) for x in sel.split(",") if x.strip().isdigit()]
            return [countries[i-1]["egName"] for i in indices if 1 <= i <= len(countries)]
        except Exception:
            print("输入无效，请重新输入")

def harvest_and_activate(base, token, hdrs, codes, residence, target, do_activate):
    """拉取节点（复用同一 requestid），逐节点激活，只保留激活成功的。"""
    collected = {c: {} for c in codes}
    rounds = 0
    while True:
        rounds += 1
        for code in codes:
            if target and len(collected[code]) >= target:
                continue
            d = fetch_nodes(base, token, hdrs, code, residence)
            nodes = d.get("data") or []
            for n in nodes:
                dn = n.get("domainName")
                if dn in collected[code]:
                    continue
                if do_activate:
                    ok = activate_node(n)
                    n = dict(n)
                    n["_activated"] = ok
                    if ok:
                        collected[code][dn] = n
                    else:
                        print(f"    ✗ {code} {dn[:24]} 激活失败（data:false，跳过）")
                else:
                    n = dict(n)
                    n["_activated"] = None
                    collected[code][dn] = n
            if nodes:
                print(f"  ✓ {code}: 已激活 {len(collected[code])}{'/' + str(target) if target else ''}")
        missing = [c for c in codes if target and len(collected[c]) < target]
        if not target or not missing:
            break
        if rounds >= 300:
            print("  ⚠ 达到轮次上限(300)，停止")
            break
        time.sleep(0.4)
    return collected

# ================================================================
# main
# ================================================================
def main():
    ap = argparse.ArgumentParser(description="DeVPN 节点拉取+激活（单文件）")
    ap.add_argument("--no-activate", action="store_true", help="只拉取不激活（调试）")
    ap.add_argument("--android-id", default=None, help="指定 16 位 hex android_id（默认随机）")
    ap.add_argument("--token", default=DEFAULT_TOKEN, help="指定 token")
    ap.add_argument("--code", default=None, help="非交互：国家代码，逗号分隔（如 HK,JP,SG）")
    ap.add_argument("--target", type=int, default=0, help="非交互：每个国家目标节点数（默认1轮）")
    ap.add_argument("--residence", action="store_true", help="拉取家庭住宅节点")
    ap.add_argument("--out", default=None, help="输出文件路径（默认 ~/Downloads/nodes_时间戳.txt）")
    args = ap.parse_args()

    device_id = args.android_id or "".join(random.choice("0123456789abcdef") for _ in range(16))
    hdrs = make_headers(args.token, device_id)
    print(f"→ android_id: {device_id}")
    print(f"→ requestid:  {hdrs['requestid'][:60]}...（全程复用）")

    # 探测可用域名
    base = None
    for d in DOMAINS:
        r = fetch_nodes(d, args.token, hdrs, "HK")
        ok = r.get("code") == 0 and r.get("data")
        print(f"  {'✓' if ok else '✗'} {d}  code={r.get('code')}  nodes={len(r.get('data') or [])}")
        if ok and base is None:
            base = d
    if not base:
        print("✗ 所有域名都无法拉到节点，token 可能失效")
        sys.exit(1)
    print(f"→ 使用 API 域名: {base}")

    if args.code:
        codes = [c.strip().upper() for c in args.code.split(",") if c.strip()]
        residence = args.residence
        target = args.target
    else:
        residence = input("是否拉取家庭住宅节点？(y/n，默认 n): ").strip().lower() == 'y'
        codes = select_countries(base, args.token, hdrs, residence)
        if not codes:
            print("未选择任何国家，退出")
            return
        ans = input("\n每个国家目标节点数（回车=只拉1轮约3个）: ").strip()
        target = int(ans) if ans.isdigit() and int(ans) > 0 else 0

    do_activate = not args.no_activate
    print(f"\n===== 开始拉取{'并激活' if do_activate else '（不激活）'} =====")
    collected = harvest_and_activate(base, args.token, hdrs, codes, residence, target, do_activate)

    all_links = []
    for code in codes:
        for i, n in enumerate(collected[code].values()):
            name = f"DeVPN-{'RES' if residence else 'IDC'}-{code}-{i}"
            all_links.append(vmess_link(n, name))
    print(f"\n合计 {len(all_links)} 条（已按域名去重{'，均为激活成功节点' if do_activate else ''}）")

    if all_links:
        if args.out:
            save_path = args.out
        else:
            ts = time.strftime("%Y%m%d_%H%M%S")
            save_path = os.path.join(SAVE_DIR, f"nodes_{ts}.txt")
        os.makedirs(os.path.dirname(save_path) or ".", exist_ok=True)
        with open(save_path, "w", encoding="utf-8") as f:
            f.write("\n".join(all_links) + "\n")
        print(f"\n✅ 节点已保存（{len(all_links)} 条）到 {save_path}")
    else:
        print("⚠️ 未获取到任何可用节点，未保存文件")

if __name__ == "__main__":
    main()
