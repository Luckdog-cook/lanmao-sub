#!/usr/bin/env python3
"""DeVPN 一键拉节点（单文件，拷走即可跑）

    python3 devpn.py

流程：自动注册新账号 → 绑邀请码 → 领免费时长
     → 各地区并发各拉 10 轮并激活 → 保存 nodes.txt / last_account.json

依赖：
  - Python 3
  - cryptography 或 pynacl（二选一，用于 ed25519 注册签名）
        pip install cryptography
  - 能访问外网

不需要其它本地文件、配置、数据库。
"""
import base64
import hashlib
import json
import os
import random
import ssl
import sys
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request

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
# 内嵌：base58（Solana 公钥 / 签名编码）
# ================================================================
_B58_ALPH = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = bytearray()
    while n > 0:
        n, r = divmod(n, 58)
        out.append(_B58_ALPH[r])
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return (b"1" * pad + out[::-1]).decode("ascii")

def ed25519_keypair():
    """返回 (public_raw_32, sign_fn)，sign_fn(msg:bytes)->sig64。"""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        seed = os.urandom(32)
        sk = Ed25519PrivateKey.from_private_bytes(seed)
        pub = sk.public_key().public_bytes_raw()
        return pub, (lambda msg, _sk=sk: _sk.sign(msg))
    except Exception:
        pass
    try:
        from nacl.signing import SigningKey
        sk = SigningKey.generate()
        pub = bytes(sk.verify_key)
        return pub, (lambda msg, _sk=sk: _sk.sign(msg).signature)
    except Exception as e:
        raise RuntimeError(
            "需要 ed25519 支持：请安装 cryptography 或 pynacl\n"
            "  pip install cryptography\n"
            f"原始错误: {e}"
        )

# ================================================================
# 配置
# ================================================================
DEFAULT_INVITE = "TVX2A2N0"
OWNER_ID = "f53dbff288fc5090"
WS_PATH = "/ws-vmess"
DEVICE_BRAND = "motorola"
DEVICE_MODEL = "XT2201-2"
DEVICE_NAME = "motorola edge X30"
DEVICE_OS = "14"
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
def make_headers(token, device_id, proof=None):
    device = {
        "brand": DEVICE_BRAND,
        "deviceId": device_id,
        "systemName": "Android",
        "isTablet": "false",
        "deviceName": DEVICE_NAME,
        "deviceModel": DEVICE_MODEL,
        "osVersion": DEVICE_OS,
        "appVersion": APP_VER,
        "platform": "android",
    }
    fingerprint = hashlib.sha256(
        json.dumps(device, separators=(",", ":")).encode()
    ).hexdigest()
    dsfunique = dsfunique_for(device_id)
    if proof is None:
        ts_ms = str(int(time.time() * 1000))
        urandom_nonce = os.urandom(16).hex()
        proof = make_proof(device_id, ts_ms, urandom_nonce)
    return {
        "dsf-token": token,
        "Language": "zh_HK",
        "x-version": APP_VER,
        "fingerprint": fingerprint,
        "manufacturer": DEVICE_BRAND,
        "platform": "android",
        "devicemodel": DEVICE_MODEL,
        "osversion": DEVICE_OS,
        "appversion": APP_VER,
        "devicename": DEVICE_NAME,
        "dsfunique": dsfunique,
        "requestid": json.dumps(proof, separators=(",", ":")),
    }

def make_login_device_info(android_id):
    """App getDeviceInfo() 字段（用于登录 fingerprint / nonce 查询）。"""
    return {
        "brand": DEVICE_BRAND,
        "deviceId": DEVICE_MODEL,
        "systemName": "Android",
        "isTablet": "false",
        "hasNotch": "false",
        "totalMemory": str(8 * 1024 ** 3),
        "totalDiskCapacity": str(128 * 1024 ** 3),
        "manufacturer": DEVICE_BRAND,
        "deviceType": "Handset",
        "androidId": android_id,
    }

def pick_base(hdrs=None):
    hdrs = hdrs or {"Language": "zh_HK"}
    for d in DOMAINS:
        st, body = http("GET", f"{d}/api/dsf/home/getByCode?code=devpn_download", hdrs)
        if body and '"code":0' in body:
            return d
    return None

def register_account(invite=DEFAULT_INVITE, android_id=None, claim_free=True):
    """生成 Solana 密钥 → 登录拿新 dsf-token → 绑邀请码 → 领免费时长。

    返回 dict: token / android_id / wallet / base / user / proof
    """
    android_id = android_id or "".join(random.choice("0123456789abcdef") for _ in range(16))
    device_info = make_login_device_info(android_id)
    fingerprint = hashlib.sha256(
        json.dumps(device_info, separators=(",", ":")).encode()
    ).hexdigest()
    proof = make_proof(android_id, str(int(time.time() * 1000)), os.urandom(16).hex())
    pub, sign = ed25519_keypair()
    wallet = b58encode(pub)

    base = pick_base()
    if not base:
        raise RuntimeError("无法连接任何 API 域名")

    qs = urllib.parse.urlencode({
        "walletAddress": wallet,
        "fingerprint": fingerprint,
        **device_info,
    })
    hdrs = {
        "Language": "zh_HK",
        "Content-Type": "application/json",
        "x-version": APP_VER,
        "platform": "android",
        "dsf-token": "",
        "fingerprint": fingerprint,
        "manufacturer": DEVICE_BRAND,
        "requestid": json.dumps(proof, separators=(",", ":")),
        "devicemodel": DEVICE_MODEL,
        "osversion": DEVICE_OS,
        "appversion": APP_VER,
        "devicename": DEVICE_NAME,
        "dsfunique": dsfunique_for(android_id),
    }
    st, body = http("GET", f"{base}/api/dsf/wallet/login/user/nonce?{qs}", hdrs)
    try:
        nonce = json.loads(body)["data"]
    except Exception:
        raise RuntimeError(f"获取 nonce 失败: {body}")

    message = str(uuid.uuid4())
    signature = b58encode(sign(message.encode("utf-8")))
    verify_body = {
        **proof,
        "fingerprint": fingerprint,
        "walletAddress": wallet,
        "signature": signature,
        "nonce": nonce,
        "message": message,
        "sourceType": "deapp_android",
        "userId": "",
        "uuid": "",
        "device": json.dumps(device_info, separators=(",", ":")),
        "deviceType": "android",
        "deviceName": DEVICE_NAME,
        "deviceModel": DEVICE_MODEL,
        "osVersion": DEVICE_OS,
        "appVersion": APP_VER,
    }
    st, body = http("POST", f"{base}/api/dsf/wallet/login/user/verify", hdrs, body=verify_body)
    try:
        resp = json.loads(body)
        data = resp["data"]
        token = data["dsf-token"]
    except Exception:
        raise RuntimeError(f"登录/注册失败: {body}")

    hdrs["dsf-token"] = token
    bind_ok = None
    free_ok = None
    if invite:
        st, body = http(
            "POST",
            f"{base}/api/dsf/wallet/app/bind-code?inviteCode={urllib.parse.quote(invite)}",
            hdrs,
            body={},
        )
        try:
            bind_ok = json.loads(body).get("code") == 0
        except Exception:
            bind_ok = False

    if claim_free:
        flat = {"fingerprint": fingerprint, **device_info, **{k: str(v) for k, v in proof.items()}}
        q2 = urllib.parse.urlencode(flat)
        st, body = http(
            "GET",
            f"{base}/api/dsf/app/home/user/get-free-flow?{q2}",
            hdrs,
        )
        try:
            free_ok = json.loads(body).get("data") is True
        except Exception:
            free_ok = False

    return {
        "token": token,
        "android_id": android_id,
        "wallet": wallet,
        "base": base,
        "user": (data or {}).get("user") or {},
        "proof": proof,
        "session_id": (data or {}).get("sessionId"),
        "expire_time": (data or {}).get("expireTime"),
        "bind_ok": bind_ok,
        "free_ok": free_ok,
        "raw": data,
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
# 一键并发拉取入口
# ================================================================
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

INVITE = DEFAULT_INVITE
HERE = os.path.dirname(os.path.abspath(__file__)) or "."
OUT_FILE = os.path.join(HERE, "nodes.txt")
META_FILE = os.path.join(HERE, "last_account.json")
ROUNDS_PER_COUNTRY = 10
COUNTRY_WORKERS = 7
ACTIVATE_WORKERS = 16

_print_lock = threading.Lock()
_activate_pool = None


def log(msg: str) -> None:
    with _print_lock:
        print(msg, flush=True)


def activate_batch(nodes):
    ok = []
    if not nodes:
        return ok
    pool = _activate_pool
    if pool is None:
        with ThreadPoolExecutor(max_workers=ACTIVATE_WORKERS) as tmp:
            futs = {tmp.submit(activate_node, n): n for n in nodes}
            for fut in as_completed(futs):
                n = futs[fut]
                try:
                    if fut.result():
                        ok.append(n)
                except Exception:
                    pass
        return ok
    futs = {pool.submit(activate_node, n): n for n in nodes}
    for fut in as_completed(futs):
        n = futs[fut]
        try:
            if fut.result():
                ok.append(n)
        except Exception:
            pass
    return ok


def harvest_country(base, token, hdrs, code, rounds=ROUNDS_PER_COUNTRY):
    bucket = {}
    log(f"开始 {code} …")
    for round_i in range(1, rounds + 1):
        before = len(bucket)
        data = fetch_nodes(base, token, hdrs, code, residence=False)
        fresh = []
        for n in data.get("data") or []:
            dn = n.get("domainName")
            if dn and dn not in bucket:
                fresh.append(n)
        for n in activate_batch(fresh):
            dn = n.get("domainName")
            if dn:
                bucket[dn] = n
        gained = len(bucket) - before
        log(f"  {code}: 第{round_i}/{rounds}轮  累计{len(bucket)}  (+{gained})")
    log(f"  → {code} 完成 {len(bucket)} 条（{rounds} 轮）")
    return code, bucket


def main():
    global _activate_pool
    t0 = time.time()

    log("===== 1/3 注册新账号 =====")
    acc = register_account(invite=INVITE, claim_free=True)
    token = acc["token"]
    device_id = acc["android_id"]
    log(f"token:  {token}")
    log(f"wallet: {acc['wallet']}")
    log(
        f"invite: {'ok' if acc.get('bind_ok') else 'fail'}  "
        f"free: {'ok' if acc.get('free_ok') else 'fail'}"
    )

    hdrs = make_headers(token, device_id)
    base = acc.get("base")
    if not base:
        for d in DOMAINS:
            r = fetch_nodes(d, token, hdrs, "HK")
            if r.get("code") == 0 and r.get("data"):
                base = d
                break
    if not base:
        log("无法连接 API")
        sys.exit(1)
    log(f"API: {base}")

    log("\n===== 2/3 并发拉取全部国家节点 =====")
    countries = get_countries(base, token, hdrs, residence=False)
    if not countries:
        log("国家列表为空")
        sys.exit(1)

    codes = [c.get("egName") for c in countries if c.get("egName")]
    log(
        f"国家 {len(codes)} 个，每国 {ROUNDS_PER_COUNTRY} 轮，"
        f"地区并发 {COUNTRY_WORKERS}，激活并发 {ACTIVATE_WORKERS}"
    )
    for c in countries:
        log(f"  - {c.get('egName')}: {c.get('name')} ({c.get('total', 0)})")

    collected = {}
    _activate_pool = ThreadPoolExecutor(max_workers=ACTIVATE_WORKERS)
    try:
        with ThreadPoolExecutor(max_workers=min(COUNTRY_WORKERS, len(codes) or 1)) as pool:
            futs = [
                pool.submit(harvest_country, base, token, hdrs, code)
                for code in codes
            ]
            for fut in as_completed(futs):
                code, bucket = fut.result()
                collected[code] = bucket
    finally:
        _activate_pool.shutdown(wait=True)
        _activate_pool = None

    ordered = {code: collected[code] for code in codes if code in collected}

    log("\n===== 3/3 保存 =====")
    links = []
    for code, nodes in ordered.items():
        for i, n in enumerate(nodes.values()):
            links.append(vmess_link(n, f"DeVPN-{code}-{i}"))

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(links) + "\n")

    elapsed = time.time() - t0
    meta = {
        "token": token,
        "android_id": device_id,
        "wallet": acc["wallet"],
        "invite": INVITE,
        "rounds_per_country": ROUNDS_PER_COUNTRY,
        "country_workers": COUNTRY_WORKERS,
        "activate_workers": ACTIVATE_WORKERS,
        "per_country": {k: len(val) for k, val in ordered.items()},
        "total_links": len(links),
        "elapsed_sec": round(elapsed, 1),
        "nodes_file": OUT_FILE,
    }
    with open(META_FILE, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    log(f"合计 {len(links)} 条 → {OUT_FILE}")
    log(f"账号信息 → {META_FILE}")
    log(f"耗时 {elapsed:.1f}s")
    for k, n in meta["per_country"].items():
        log(f"  {k}: {n}")


if __name__ == "__main__":
    main()
