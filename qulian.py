#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
趣连固定订阅自动更新版 - 优化版（含 Clash 输出 + 原始节点名称）
"""

import base64
import hashlib
import io
import json
import os
import random
import string
import sys
import threading
import time
import urllib.parse
import urllib.request
import argparse
import logging
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

USE_OCR_ENGINE = None
_DDDD_OCR_INSTANCE = None

try:
    import pytesseract
    USE_OCR_ENGINE = "tesseract"
except ImportError:
    try:
        import ddddocr
        USE_OCR_ENGINE = "ddddocr"
    except ImportError:
        pass

from PIL import Image, ImageSequence, ImageOps
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Util.Padding import pad, unpad

BASE_URLS = [
    "https://api2.zestlink.com:48574/vpn/api",
    "https://api.zestlink.com/vpn/api",
    "https://47.86.62.170/vpn/api",
]

VERSION = "170"
SYSTEM_TYPE = "Android"
DEVICE_MODEL = "XT2201_2"
UA = f"Mozilla/5.0 (Linux; Android 14; {DEVICE_MODEL}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
AES_IV = b"9583012938476028"
_RSA_XOR_KEY = "qLv9aK2vP0x#"

_RSA_PRIV_B64 = "PAU/egU8ezQRdDltMysdSAkgWzFpR0hhMB0zfyAKYTURXT1UFis8XSAsdzcRXz9hMAEef1YuViMDQAwTJXkXcgx/fC4bew13RxkyXyQKU09heFNxKXowbFgAezJjUjtwJSU9FhYbVhMqfE5vRCIkAVAFSgViWQkbJSoafjMAAw8cSRtlPBw/ThAsBAYcZTJ1BiASYwoRQB42ehdqQjonTisvQCcWcy0aNypCdQs+QT9odA9FSBUEWylzCyUfRDBURXwbcwgGWQIdQTlsOHsmckp5eiwbexNKKQsAayAsfzQRcT1gFhUzeBJ/SiEUdi8VGBU/di8NaiQkdEEXBHU8Xgkaf0Q1cSxoPx43WlIyfQMbXUxaQzYwXwopdV0TABB7KAMwf1NyRgcyQVMbPQ8/U0opBwEgVAsMBgEcWxEhBD85ZEgaQD8/TwwzWRgyfkB1KWNGag4YWzc7ZwFHWjU0UxVyXTk7fypFAztBDVMiXR8fXTFzOwtPATgkRxQgWBx5OAE8XFkNZB0+d05RIyldfCARAjUBYTwSOzgbWxUdWRw4RA90An4PXycgCgQWXlNzQQQ+YxAoABQxQRR5Fxs7aipyZhVmdxBnHgMsdTAERRM2YAJpP3QzCA4dWjBlGwFGJCgZWFE+WSQjWRdBMCczeFEYeQM1SE1mBAUbUCcNaxMbaTtsFwQRSBMkXEZmcg4IHT4jXk4BATQEQzcWRA4dahA6BF06alcbBhgbdDR7QE8fWCxMISsMYS0ffjw/ZSJqCHo1XgY8eDQRfDF5An4vcVYuaE84AFNkAjwVQSgtQAAjZyxtCz0faTQISh1lYAwVBAUETyMaXRkIVhtJRS0FQDR6VR9/ajZhCCc3Vih4ZDBpYS5FWig3WyAtc0cfBRNgIAkAC1MsYiM5Ux1aNTw8TAQSY1kjRzB5PAhdClE6eRFgeR5ZFgMcUQIDBRkiASliNn8PTU4lCkJpQhRmRzsfQC55QBs2ShRwBT4/Ty4TVTccek9aJgQFejAPcQIDVQwSKTkcSzIPYkQAaipTPHkzeFY6dwA3Y0oMNz5DUTMzeywodxkMBh9GTgMDXRIidBxJNH4XDwQ7ZQEAZk1iQCIeDyYmXkEdXCBnMwABfy0RY0s="

_RSA_PUB_B64 = "PAUxXywKAjETYwlkIgUUCiUadzQRYS1iMHgxdyAPcTQ5YTNhFh01XikABRgVAgJuQjYdYA4MAycWQQ1vGzUyYTAbWy8HWE9HBHsHDjgxWSYiCE16CDYAY1gHREAqdTFHMCM9XBBgQSQRVzBLRjVZYQASYjQHaTZSGiIndSUtQgMEcjlnAjZOTCZ6QDVnUUxWHX4jAStgBT84BCkaQzs3dg0mXkAFaUBaMg1AbxAFZUFpRixNRhoUbSspATMCd0F6IiQSYwp5UEM/VjxqMgtBbSkaezIRYTlh"

_PRINT_LOCK = threading.Lock()
CONCURRENCY = 6
MAX_NODES = 80
CAPTCHA_MAX_RETRIES = 10

OUT_DIR = Path(os.getenv("OUT_DIR", Path.cwd()))
NODES_FILE = OUT_DIR / "nodes.txt"
SUB64_FILE = OUT_DIR / "qulian_nodes_base64"
CLASH_FILE = OUT_DIR / "qulian_clash.yaml"
INFO_FILE = OUT_DIR / "subscription_info.txt"

logger = logging.getLogger("趣连")


def setup_logging(verbose=False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
        force=True,
    )


_PRIV_KEY = None
_PUB_KEY = None


def _xor_decode(b64: str, key: str) -> str:
    raw = base64.b64decode(b64).decode("latin1")
    return "".join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(raw))


def _init_modules():
    global _PRIV_KEY, _PUB_KEY, _DDDD_OCR_INSTANCE
    if _PRIV_KEY is None:
        priv_der = base64.b64decode(_xor_decode(_RSA_PRIV_B64, _RSA_XOR_KEY))
        pub_der = base64.b64decode(_xor_decode(_RSA_PUB_B64, _RSA_XOR_KEY))
        _PRIV_KEY = RSA.import_key(priv_der)
        _PUB_KEY = RSA.import_key(pub_der)
    if USE_OCR_ENGINE == "ddddocr" and _DDDD_OCR_INSTANCE is None:
        import ddddocr
        _DDDD_OCR_INSTANCE = ddddocr.DdddOcr(show_ad=False)


def aes_encrypt(plaintext: bytes, key: bytes) -> str:
    cipher = AES.new(key[:16], AES.MODE_CBC, AES_IV)
    return base64.b64encode(cipher.encrypt(pad(plaintext, 16))).decode()


def aes_decrypt(b64: str, key: bytes) -> str:
    cipher = AES.new(key[:16], AES.MODE_CBC, AES_IV)
    return unpad(cipher.decrypt(base64.b64decode(b64)), 16).decode("utf-8")


def rsa_encrypt_pkcs1(plaintext: bytes) -> str:
    return base64.b64encode(PKCS1_v1_5.new(_PUB_KEY).encrypt(plaintext)).decode()


def rsa_decrypt_pkcs1(b64: str) -> bytes:
    return PKCS1_v1_5.new(_PRIV_KEY).decrypt(base64.b64decode(b64), None) or b""


def rsa_sign_sha256(message: str) -> str:
    k = _PRIV_KEY.size_in_bytes()
    digest = hashlib.sha256(message.encode()).digest()
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420")
    t = digest_info + digest
    em = b"\x00\x01" + b"\xff" * (k - 3 - len(t)) + b"\x00" + t
    sig = pow(int.from_bytes(em, "big"), _PRIV_KEY.d, _PRIV_KEY.n)
    return base64.b64encode(sig.to_bytes(k, "big")).decode()


def canon_json(v) -> str:
    if v is None: return ""
    if isinstance(v, list): return "[" + ",".join(canon_json(x) or "null" for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(k for k in v if v[k] is not None)
        return "{" + ",".join(json.dumps(k, ensure_ascii=False, separators=(",", ":")) + ":" + canon_json(v[k]) for k in keys) + "}"
    return json.dumps(v, ensure_ascii=False, separators=(",", ":"))


def _nonce(length=16):
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(length))


def api_request(path: str, method: str, data: dict, token: str = "", imei: str = "", extra_headers: dict = None, timeout: int = 15):
    last_err = None
    for base in BASE_URLS:
        try:
            ts = str(int(time.time() * 1000))
            nonce = _nonce(16)
            aes_key = _nonce(16)
            plaintext = canon_json(data)
            body = {
                "encryptData": aes_encrypt(plaintext.encode("utf-8"), aes_key.encode()),
                "encryptKey": rsa_encrypt_pkcs1(aes_key.encode()),
            }
            sign_path = "/vpn/api" + path
            signature = rsa_sign_sha256(f"{ts}\n{nonce}\n{sign_path}\n{plaintext}")
            trace = aes_encrypt(f"{ts}|{nonce}|{path}|{int(time.time())}".encode(), nonce.encode())

            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "version": VERSION,
                "System-Type": SYSTEM_TYPE,
                "Device": imei or "",
                "User-Agent": UA,
                "X-Req-Timestamp": ts,
                "X-Req-Nonce": nonce,
                "X-Req-Signature": signature,
                "X-Client-Trace": trace,
                "X-Client-Debug": "0",
            }
            if token:
                headers["VPN-USER-TOKEN"] = token
            if extra_headers:
                headers.update(extra_headers)

            if method == "GET":
                qs = f"encryptData={urllib.parse.quote(body['encryptData'], safe='')}&encryptKey={urllib.parse.quote(body['encryptKey'], safe='')}"
                url = base + path + ("&" if "?" in path else "?") + qs
                req = urllib.request.Request(url, headers=headers, method="GET")
            else:
                req = urllib.request.Request(base + path, data=json.dumps(body).encode(), headers=headers, method=method)

            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = json.loads(resp.read().decode("utf-8"))

            if isinstance(raw, dict) and raw.get("encrypted") and raw.get("data"):
                key = rsa_decrypt_pkcs1(raw["encrypted"])
                return json.loads(aes_decrypt(raw["data"], key))
            return raw
        except Exception as ex:
            last_err = ex
            time.sleep(0.3)
    raise RuntimeError(f"API 请求失败 ({path}): {last_err}")


def get_captcha_image(imei: str) -> tuple:
    for base in BASE_URLS:
        try:
            url = f"{base}/captcha/image"
            req = urllib.request.Request(url, headers={
                "Device": imei,
                "version": VERSION,
                "User-Agent": UA,
            })
            with urllib.request.urlopen(req, timeout=10) as resp:
                headers = dict(resp.getheaders())
                uuid = headers.get("X-Captcha-Uuid") or headers.get("x-captcha-uuid")
                img_bytes = resp.read()
                if uuid and img_bytes and img_bytes[:4] in (b"GIF8", b"\x89PNG"):
                    return uuid, img_bytes
        except Exception:
            continue
    raise RuntimeError("获取验证码失败")


def solve_animated_captcha(img_bytes: bytes) -> str:
    if not USE_OCR_ENGINE:
        raise RuntimeError("未安装 OCR 引擎")
    try:
        im = Image.open(io.BytesIO(img_bytes))
        candidates = []
        for frame in ImageSequence.Iterator(im):
            rgb = frame.convert("RGB")
            bg_color = rgb.getpixel((0, 0))
            padded = ImageOps.expand(rgb, border=18, fill=bg_color)
            code = ""
            if USE_OCR_ENGINE == "tesseract":
                gray = padded.convert("L")
                bin_img = gray.point(lambda p: 255 if p > 135 else 0)
                tess_cfg = r"--psm 7 -c tessedit_char_whitelist=0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                raw_text = pytesseract.image_to_string(bin_img, config=tess_cfg)
                code = "".join(ch for ch in raw_text if ch.isalnum()).strip().lower()
            elif USE_OCR_ENGINE == "ddddocr":
                buf = io.BytesIO()
                padded.save(buf, format="PNG")
                code = _DDDD_OCR_INSTANCE.classification(buf.getvalue()).strip().lower()
            if len(code) == 5 and code.isalnum():
                candidates.append(code)
        if candidates:
            return Counter(candidates).most_common(1)[0][0]
    except Exception:
        pass
    return ""


def auto_register_with_captcha(email: str, password: str, imei: str, max_retries: int = CAPTCHA_MAX_RETRIES) -> str:
    for attempt in range(1, max_retries + 1):
        try:
            uuid, img_bytes = get_captcha_image(imei)
            code = solve_animated_captcha(img_bytes)
            if not code or len(code) != 5:
                time.sleep(0.8 + random.random() * 0.7)
                continue
            extra_headers = {
                "X-Sign-Up": "1",
                "X-Captcha-Uuid": uuid,
                "X-Captcha-Code": code,
            }
            r = api_request("/user/signup", "POST", {"name": email, "password": password}, imei=imei, extra_headers=extra_headers)
            if isinstance(r, dict) and r.get("token"):
                logger.info("第 %d 次识别成功 → %s", attempt, code)
                return r["token"]
            elif isinstance(r, dict) and r.get("code") == 180:
                time.sleep(1.0 + random.random())
                continue
        except Exception as ex:
            logger.warning("第 %d 次失败: %s", attempt, ex)
            time.sleep(1.2 + random.random())
    raise RuntimeError(f"连续 {max_retries} 次验证码失败")


def gen_email():
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10)) + "@zestlink.example.com"


def gen_password():
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(12))


def gen_imei():
    return "".join(random.choice("0123456789ABCDEF") for _ in range(32))


# ---------- 名称提取 ----------

def get_node_display_name(nd: dict) -> str:
    """从节点列表项里尽量提取 App 里显示的原始名称"""
    if not isinstance(nd, dict):
        return ""
    # 常见字段名，按优先级尝试
    for k in ("name", "nodeName", "node_name", "title", "remark", "remarks",
              "alias", "displayName", "display_name", "serverName", "server_name"):
        v = nd.get(k)
        if v is not None and str(v).strip():
            return str(v).strip()
    # 再尝试嵌套结构
    for k in ("node", "info", "data"):
        sub = nd.get(k)
        if isinstance(sub, dict):
            for kk in ("name", "nodeName", "title", "remark", "displayName"):
                v = sub.get(kk)
                if v is not None and str(v).strip():
                    return str(v).strip()
    return ""


# ---------- 协议配置解析 ----------

def parse_leaf_trojan(cfg: str):
    proto = host = port = password = sni = None
    for idx, line in enumerate((cfg or "").splitlines()):
        line = line.strip()
        if line.startswith("Proxy =") and "direct" not in line.lower():
            spec = line[len("Proxy ="):]
            for nxt in (cfg or "").splitlines()[idx + 1:]:
                nxt = nxt.strip()
                if nxt.startswith("["): break
                spec += nxt
            parts = [p.strip() for p in spec.split(",")]
            proto, host, port = (parts + [None] * 3)[:3]
            for p in parts[3:]:
                pl = p.lower()
                if pl.startswith("password="): password = p.split("=", 1)[1]
                elif pl.startswith("sni="): sni = p.split("=", 1)[1]
            break
    return proto, host, port, password, sni


def parse_vless_config(cfg: str):
    d, reality = {}, {}
    for line in (cfg or "").splitlines():
        if ":" not in line: continue
        raw_k, raw_v = line.split(":", 1)
        k = raw_k.strip().lower()
        v = raw_v.strip()
        if not k or not v: continue
        if k == "reality-opts":
            for part in v.strip("{}").split(","):
                if ":" in part:
                    rk_raw, rv_raw = part.split(":", 1)
                    rk = rk_raw.strip().lower().replace("-", "_")
                    reality[rk] = rv_raw.strip()
        else:
            d[k] = v
    return {**d, "reality": reality} if d.get("type") == "vless" and d.get("server") else None


def parse_config(cfg: str):
    if not cfg: return None
    low = cfg.lower()
    if "type: vless" in low:
        if v := parse_vless_config(cfg): return {"kind": "vless", "data": v}
    if "proxy =" in low or "[proxy]" in low:
        proto, host, port, pwd, sni = parse_leaf_trojan(cfg)
        if proto: return {"kind": "trojan", "data": {"host": host, "port": port, "password": pwd, "sni": sni}}
    return None


# ---------- 链接生成 ----------

def make_vless_link(server, port, uuid, flow, sni, fp, pbk, sid, name) -> str:
    params = {"encryption": "none", "security": "reality", "type": "tcp"}
    if sni: params["sni"] = sni
    if fp: params["fp"] = fp
    if pbk: params["pbk"] = pbk
    if sid: params["sid"] = sid
    if flow: params["flow"] = flow
    q = urllib.parse.urlencode(params)
    return f"vless://{uuid}@{server}:{port}?{q}#{urllib.parse.quote(name)}"


def make_trojan_link(name, host, port, password, sni) -> str:
    q = urllib.parse.urlencode({"sni": sni or host, "security": "tls", "type": "tcp"})
    return f"trojan://{urllib.parse.quote(password or '', safe='')}@{host}:{port}?{q}#{urllib.parse.quote(name)}"


# ---------- Clash 生成 ----------

def _yaml_quote(s) -> str:
    if s is None:
        return '""'
    s = str(s)
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def make_clash_proxy(d: dict, name: str) -> dict:
    """把解析后的节点转成 Clash/Meta proxy dict，name 使用 App 原始名称"""
    if d["kind"] == "trojan":
        p = {
            "name": name,
            "type": "trojan",
            "server": d["host"],
            "port": int(d["port"]),
            "password": d.get("password") or "",
            "udp": True,
            "skip-cert-verify": False,
        }
        if d.get("sni"):
            p["sni"] = d["sni"]
        return p

    if d["kind"] == "vless":
        p = {
            "name": name,
            "type": "vless",
            "server": d["host"],
            "port": int(d["port"]),
            "uuid": d["uuid"],
            "udp": True,
            "tls": True,
            "network": "tcp",
            "servername": d.get("sni") or d["host"],
            "client-fingerprint": d.get("fp") or "chrome",
        }
        if d.get("flow"):
            p["flow"] = d["flow"]
        if d.get("pbk"):
            p["reality-opts"] = {
                "public-key": d["pbk"],
                "short-id": d.get("sid") or "",
            }
        return p

    return None


def build_clash_proxies(details: list) -> list:
    """按 App 原始名称生成 Clash 代理，重名自动加 (2)、(3)..."""
    counter = {}
    result = []
    for d in details:
        base = d.get("name") or f"{d.get('countryCode', 'XX').upper()}-{d.get('host', 'unknown')}"
        counter[base] = counter.get(base, 0) + 1
        n = counter[base]
        name = base if n == 1 else f"{base} ({n})"
        p = make_clash_proxy(d, name)
        if p:
            result.append(p)
    return result


def build_clash_yaml(proxies: list) -> str:
    """手写 YAML，避免依赖 pyyaml"""
    lines = []
    lines.append("# 趣连自动订阅 (Clash Meta / mihomo)")
    lines.append(f"# 更新时间: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    lines.append(f"# 节点数: {len(proxies)}")
    lines.append("")
    lines.append("mixed-port: 7890")
    lines.append("allow-lan: false")
    lines.append("mode: rule")
    lines.append("log-level: info")
    lines.append("")
    lines.append("proxies:")

    for p in proxies:
        lines.append(f"  - name: {_yaml_quote(p['name'])}")
        lines.append(f"    type: {p['type']}")
        lines.append(f"    server: {_yaml_quote(p['server'])}")
        lines.append(f"    port: {p['port']}")
        if p["type"] == "trojan":
            lines.append(f"    password: {_yaml_quote(p['password'])}")
            lines.append(f"    udp: {str(p.get('udp', True)).lower()}")
            if p.get("sni"):
                lines.append(f"    sni: {_yaml_quote(p['sni'])}")
        elif p["type"] == "vless":
            lines.append(f"    uuid: {_yaml_quote(p['uuid'])}")
            lines.append(f"    udp: {str(p.get('udp', True)).lower()}")
            lines.append(f"    tls: {str(p.get('tls', True)).lower()}")
            lines.append(f"    network: {p.get('network', 'tcp')}")
            if p.get("servername"):
                lines.append(f"    servername: {_yaml_quote(p['servername'])}")
            if p.get("client-fingerprint"):
                lines.append(f"    client-fingerprint: {p['client-fingerprint']}")
            if p.get("flow"):
                lines.append(f"    flow: {_yaml_quote(p['flow'])}")
            if p.get("reality-opts"):
                lines.append("    reality-opts:")
                lines.append(f"      public-key: {_yaml_quote(p['reality-opts']['public-key'])}")
                lines.append(f"      short-id: {_yaml_quote(p['reality-opts'].get('short-id', ''))}")

    lines.append("")
    lines.append("proxy-groups:")
    lines.append('  - name: "自动选择"')
    lines.append("    type: url-test")
    lines.append('    url: "http://www.gstatic.com/generate_204"')
    lines.append("    interval: 300")
    lines.append("    tolerance: 50")
    lines.append("    proxies:")
    for p in proxies:
        lines.append(f"      - {_yaml_quote(p['name'])}")
    lines.append('  - name: "节点选择"')
    lines.append("    type: select")
    lines.append("    proxies:")
    lines.append('      - "自动选择"')
    lines.append('      - "DIRECT"')
    for p in proxies:
        lines.append(f"      - {_yaml_quote(p['name'])}")

    lines.append("")
    lines.append("rules:")
    lines.append("  - GEOIP,LAN,DIRECT,no-resolve")
    lines.append("  - GEOIP,CN,DIRECT")
    lines.append("  - MATCH,节点选择")
    lines.append("")

    return "\n".join(lines)


# ---------- 节点抓取 ----------

def fetch_one_node(nd: dict, token: str, imei: str, idx: int, total: int):
    node_id = nd.get("nodeId")
    cc = nd.get("countryCode", "XX")
    app_name = get_node_display_name(nd)
    try:
        d = api_request("/nodes/vipConnect", "POST", {"nodeId": node_id}, token, imei, timeout=12)
        if not isinstance(d, dict) or not d.get("configFile"):
            return None
        cfg = parse_config(d.get("configFile", ""))
        if not cfg: return None
        c = cfg["data"]
        rec = {"kind": cfg["kind"], "countryCode": cc}
        if cfg["kind"] == "trojan":
            rec.update({"host": c.get("host"), "port": c.get("port"),
                        "password": c.get("password"), "sni": c.get("sni")})
        elif cfg["kind"] == "vless":
            rec.update({
                "host": c.get("server"), "port": c.get("port"), "uuid": c.get("uuid"),
                "flow": c.get("flow"), "sni": c.get("servername"),
                "fp": c.get("client-fingerprint"),
                "pbk": c.get("reality", {}).get("public_key") or "",
                "sid": c.get("reality", {}).get("short_id") or ""
            })

        # 名称：优先用 App 里的原始名称，取不到才回退
        rec["name"] = app_name or f"{str(cc).upper()}-{rec.get('host', 'unknown')}"
        rec["app_name"] = app_name

        with _PRINT_LOCK:
            print(f"\r进度: {idx}/{total} | {cc} OK", end="", flush=True)
        return rec
    except Exception:
        with _PRINT_LOCK:
            print(f"\r进度: {idx}/{total} | {cc} FAIL", end="", flush=True)
        return None


# ---------- 主流程 ----------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    setup_logging(args.verbose)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    _init_modules()
    logger.info("OCR 引擎: %s", USE_OCR_ENGINE.upper() if USE_OCR_ENGINE else "无")

    email = gen_email()
    password = gen_password()
    imei = gen_imei()
    logger.info("虚拟账号: %s", email)

    logger.info("[1/4] 自动识别验证码并注册...")
    token = auto_register_with_captcha(email, password, imei)
    logger.info("注册成功")

    time.sleep(0.5 + random.random())

    logger.info("[2/4] 检查福利...")
    try:
        cd = api_request("/welfare/countdown", "GET", {}, token, imei)
        if isinstance(cd, dict) and cd.get("canClaim") is True:
            api_request("/welfare/claim", "POST", {}, token, imei)
            logger.info("已领取福利")
    except Exception:
        pass

    logger.info("[3/4] 获取节点列表...")
    nodes = api_request("/nodes/list/all?supportSubscriptionNode=1", "GET", {}, token, imei)
    if not isinstance(nodes, list):
        raise RuntimeError("节点列表获取失败")

    if len(nodes) > MAX_NODES:
        nodes = random.sample(nodes, MAX_NODES)

    logger.info("共处理 %d 个节点", len(nodes))

    details = []
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
        futures = {executor.submit(fetch_one_node, nd, token, imei, i, len(nodes)): i
                   for i, nd in enumerate(nodes, 1)}
        for fut in as_completed(futures):
            try:
                res = fut.result(timeout=20)
                if res:
                    details.append(res)
            except Exception:
                pass

    print()
    logger.info("[4/4] 成功解析 %d 个节点", len(details))

    # 明文链接（使用 App 原始名称）
    links = []
    for d in details:
        name = d.get("name") or f"{str(d.get('countryCode', 'XX')).upper()}-{d.get('host', 'unknown')}"
        try:
            if d["kind"] == "trojan":
                links.append(make_trojan_link(name, d["host"], d["port"], d["password"], d.get("sni")))
            elif d["kind"] == "vless":
                links.append(make_vless_link(
                    d["host"], d["port"], d["uuid"],
                    d.get("flow") or "xtls-rprx-vision",
                    d.get("sni") or d["host"],
                    d.get("fp") or "chrome",
                    d.get("pbk"), d.get("sid"), name
                ))
        except Exception:
            continue

    links = list(dict.fromkeys(links))
    plain = "\n".join(links) + "\n" if links else ""
    b64 = base64.b64encode(plain.encode("utf-8")).decode("ascii") if links else ""

    # Clash 代理（同样使用 App 原始名称，重名自动编号）
    clash_proxies = build_clash_proxies(details)
    clash_yaml = build_clash_yaml(clash_proxies) if clash_proxies else ""

    info = (
        f"# 趣连自动订阅\n"
        f"# 更新时间: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n"
        f"# 节点数: {len(links)}\n"
        f"# Clash 节点数: {len(clash_proxies)}\n"
    )

    NODES_FILE.write_text(plain, encoding="utf-8")
    SUB64_FILE.write_text(b64, encoding="utf-8")
    CLASH_FILE.write_text(clash_yaml, encoding="utf-8")
    INFO_FILE.write_text(info, encoding="utf-8")

    logger.info("已写入 %d 个节点（Clash: %d）", len(links), len(clash_proxies))
    return 0 if links else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        logging.error("%s", e)
        sys.exit(1)
