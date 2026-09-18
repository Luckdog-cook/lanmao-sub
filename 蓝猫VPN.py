#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
蓝猫VPN 智能订阅脚本（最终完整优化版）
手机 + GitHub / Gitee 固定订阅自动更新专用
"""

import sys, os, json, base64, random, string, ssl, time, logging, argparse, socket, hashlib, concurrent.futures
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, List
from urllib.parse import urlparse

try:
    import urllib.request as ur
    import urllib.error
except ImportError:
    sys.exit("需要 Python 3")

# ======================== 配置（一般不用改） ========================
BOOT_URL = "https://qiyusur.oss-cn-shanghai.aliyuncs.com/2002552026.log"
FALLBACK_GATEWAY = "http://8.210.52.158:8020"
UA = "okhttp/4.12.0"
TOKEN_MAX_AGE = 3 * 24 * 3600
GATEWAY_CACHE_TTL = 6 * 3600
DEFAULT_PASSWORD = os.getenv("VPN_PASSWORD", "Py12345678")
HTTP_RETRIES = 3
HTTP_TIMEOUT = 18

# 协议过滤（空=全部保留，想只留某些协议就填，例如 ["vless", "trojan"]）
ALLOWED_PROTOCOLS: List[str] = []

# 延迟测试（默认开启）
ENABLE_LATENCY_TEST = os.getenv("VPN_TEST_LATENCY", "1") != "0"   # 设为 0 可关闭
LATENCY_TIMEOUT = 2.2
MAX_LATENCY_MS = 1100
LATENCY_WORKERS = 16

# Token 加密密钥（强烈建议在 GitHub Secrets 里设置）
ENCRYPT_KEY = os.getenv("VPN_ENCRYPT_KEY", "").strip()

# 额外输出目录（镜像用，逗号分隔）
EXTRA_OUT_DIRS = [p.strip() for p in os.getenv("VPN_EXTRA_OUT", "").split(",") if p.strip()]
# ==================================================================

OUT_DIR = Path(os.getenv("VPN_OUT_DIR", Path(__file__).resolve().parent if "__file__" in globals() else Path.cwd()))
TOKEN_FILE = OUT_DIR / "token.json"
NODES_FILE = OUT_DIR / "nodes.txt"
# 【修改点1】统一文件名，解决“更新无变化”的根源
SUB64_FILE = OUT_DIR / "bluecat_nodes_base64.txt"
CLASH_FILE = OUT_DIR / "clash.yaml"                 # 可直接导入的 Clash 配置
INFO_FILE = OUT_DIR / "subscription_info.txt"
DEVICE_FILE = OUT_DIR / "device_id.txt"
GATEWAY_CACHE_FILE = OUT_DIR / "gateway_cache.json"
LOG_FILE = OUT_DIR / "run.log"

logger = logging.getLogger("蓝猫VPN")

def setup_logging(verbose: bool = False, log_to_file: bool = True):
    level = logging.DEBUG if verbose else logging.INFO
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_to_file:
        try:
            handlers.append(logging.FileHandler(LOG_FILE, encoding="utf-8"))
        except Exception:
            pass
    logging.basicConfig(level=level, format="%(asctime)s [%(levelname)s] %(message)s",
                        datefmt="%H:%M:%S", handlers=handlers, force=True)

def _derive_key(key: str) -> bytes:
    return hashlib.sha256(key.encode("utf-8")).digest()

def encrypt_text(text: str, key: str) -> str:
    if not key: return text
    k = _derive_key(key)
    data = text.encode("utf-8")
    enc = bytes(b ^ k[i % len(k)] for i, b in enumerate(data))
    return "enc:" + base64.urlsafe_b64encode(enc).decode("ascii")

def decrypt_text(text: str, key: str) -> str:
    if not key or not text.startswith("enc:"): return text
    try:
        k = _derive_key(key)
        raw = base64.urlsafe_b64decode(text[4:].encode("ascii"))
        return bytes(b ^ k[i % len(k)] for i, b in enumerate(raw)).decode("utf-8")
    except Exception:
        return text

def get_device_id() -> str:
    if DEVICE_FILE.exists():
        try:
            did = DEVICE_FILE.read_text(encoding="utf-8").strip()
            if did: return did
        except Exception: pass
    did = "py-" + "".join(random.choices(string.hexdigits.lower(), k=12))
    try:
        DEVICE_FILE.write_text(did, encoding="utf-8")
        DEVICE_FILE.chmod(0o600)
    except Exception: pass
    return did

DEVICE_ID = get_device_id()

def http(method: str, url: str, body: Optional[dict] = None, headers: Optional[dict] = None, timeout: int = HTTP_TIMEOUT) -> Tuple[int, str]:
    h = {"User-Agent": UA, "Accept": "*/*"}
    if headers: h.update(headers)
    data = None
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        h["Content-Type"] = "application/json"
    last_err = ""
    for attempt in range(1, HTTP_RETRIES + 1):
        req = ur.Request(url, data=data, headers=h, method=method)
        try:
            with ur.urlopen(req, timeout=timeout) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except ur.error.URLError as e:
            msg = str(getattr(e, "reason", e))
            last_err = msg
            if "CERTIFICATE" in msg.upper() and attempt == 1:
                try:
                    ctx = ssl._create_unverified_context()
                    with ur.urlopen(req, timeout=timeout, context=ctx) as r:
                        return r.status, r.read().decode("utf-8", "replace")
                except Exception as e2:
                    last_err = str(e2)
            if attempt < HTTP_RETRIES: time.sleep(0.6 * attempt)
        except Exception as e:
            last_err = str(e)
            if attempt < HTTP_RETRIES: time.sleep(0.6 * attempt)
    return -1, f"ERROR: {last_err}"

def headers_for(jwt: Optional[str] = None, md5: Optional[str] = None, dev: str = "1") -> dict:
    h = {"devicetype": dev, "deviceid": DEVICE_ID, "devicename": "python-ci"}
    if jwt: h["token"] = jwt
    if md5: h["authtoken"] = md5
    return h

def get_gateway(force_refresh: bool = False) -> str:
    if not force_refresh and GATEWAY_CACHE_FILE.exists():
        try:
            cache = json.loads(GATEWAY_CACHE_FILE.read_text(encoding="utf-8"))
            if time.time() - cache.get("ts", 0) < GATEWAY_CACHE_TTL:
                gw = cache.get("gateway")
                if gw: return gw.rstrip("/")
        except Exception: pass
    st, body = http("GET", BOOT_URL)
    if st == 200:
        try:
            gw = json.loads(body).get("log")
            if gw:
                gw = gw.rstrip("/")
                try:
                    GATEWAY_CACHE_FILE.write_text(json.dumps({"gateway": gw, "ts": int(time.time())}, ensure_ascii=False), encoding="utf-8")
                except Exception: pass
                return gw
        except Exception: pass
    logger.warning("BOOT 失败，使用 fallback")
    return FALLBACK_GATEWAY

def save_token(md5_tok: str, jwt: str, email: str = "", created_at: Optional[int] = None):
    if created_at is None: created_at = int(time.time())
    data = {
        "token": md5_tok or "", "auth": jwt or "", "email": email,
        "created_at": created_at,
        "created_at_str": datetime.fromtimestamp(created_at, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "device_id": DEVICE_ID,
    }
    content = json.dumps(data, ensure_ascii=False, indent=2)
    if ENCRYPT_KEY: content = encrypt_text(content, ENCRYPT_KEY)
    TOKEN_FILE.write_text(content, encoding="utf-8")
    try: TOKEN_FILE.chmod(0o600)
    except Exception: pass
    logger.info("token 已保存%s", " [加密]" if ENCRYPT_KEY else "")

def load_token_full() -> Dict[str, Any]:
    try:
        raw = TOKEN_FILE.read_text(encoding="utf-8")
        if ENCRYPT_KEY and raw.startswith("enc:"):
            raw = decrypt_text(raw, ENCRYPT_KEY)
        return json.loads(raw)
    except Exception: return {}

def load_token() -> Tuple[str, str]:
    d = load_token_full()
    return d.get("token") or "", d.get("auth") or ""

def token_age_seconds() -> Optional[int]:
    d = load_token_full()
    created = d.get("created_at")
    return None if not created else int(time.time()) - int(created)

def is_token_expired() -> bool:
    age = token_age_seconds()
    return age is None or age >= TOKEN_MAX_AGE

def format_remain() -> str:
    age = token_age_seconds()
    if age is None: return "无有效账号"
    remain = TOKEN_MAX_AGE - age
    if remain <= 0: return "已过期"
    return f"还剩 {remain//86400}天 {(remain%86400)//3600}小时"

def rand_email() -> str:
    domains = ["gmail.com", "outlook.com", "yahoo.com", "proton.me"]
    return "py" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10)) + "@" + random.choice(domains)

def extract_host_port(link: str) -> Optional[Tuple[str, int]]:
    try:
        link = link.strip()
        if link.startswith("vmess://"):
            b64 = link[8:]
            pad = 4 - len(b64) % 4
            if pad != 4: b64 += "=" * pad
            data = json.loads(base64.b64decode(b64).decode("utf-8", "ignore"))
            host = data.get("add") or data.get("host")
            port = int(data.get("port", 0))
            if host and port: return host, port
        elif "://" in link:
            parsed = urlparse(link)
            if parsed.hostname and parsed.port: return parsed.hostname, parsed.port
            if link.startswith("ss://"):
                part = link[5:].split("#")[0]
                if "@" in part:
                    hostport = part.split("@")[-1]
                    if ":" in hostport:
                        h, p = hostport.rsplit(":", 1)
                        return h, int(p)
    except Exception: pass
    return None

def test_latency(host: str, port: int) -> Optional[float]:
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=LATENCY_TIMEOUT):
            return (time.perf_counter() - start) * 1000
    except Exception: return None

def filter_by_latency(links: List[str]) -> List[str]:
    if not ENABLE_LATENCY_TEST: return links
    logger.info("延迟测试中（保留 ≤%dms）...", MAX_LATENCY_MS)
    results = []
    def worker(link):
        hp = extract_host_port(link)
        if not hp: return link, 9999
        ms = test_latency(*hp)
        return link, ms if ms is not None else 9999
    with concurrent.futures.ThreadPoolExecutor(max_workers=LATENCY_WORKERS) as exe:
        for fut in concurrent.futures.as_completed([exe.submit(worker, l) for l in links]):
            link, ms = fut.result()
            if ms <= MAX_LATENCY_MS:
                results.append((link, ms))
    results.sort(key=lambda x: x[1])
    kept = [r[0] for r in results]
    logger.info("延迟测试完成：%d → %d 个节点", len(links), len(kept))
    return kept

def filter_and_dedup(links: List[str]) -> List[str]:
    seen, result = set(), []
    for link in links:
        link = link.strip()
        if not link: continue
        if ALLOWED_PROTOCOLS:
            proto = link.split("://", 1)[0].lower() if "://" in link else ""
            if proto not in ALLOWED_PROTOCOLS: continue
        if link not in seen:
            seen.add(link)
            result.append(link)
    return result

def write_outputs(links: List[str]):
    if not links: return
    plain = "\n".join(links) + "\n"
    b64 = base64.b64encode("\n".join(links).encode("utf-8")).decode("ascii")
    expire_ts = int(time.time()) + TOKEN_MAX_AGE
    userinfo = f"upload=0; download=0; total=10737418240; expire={expire_ts}"

    info = f"""# 蓝猫VPN 自动更新订阅
# 更新时间: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
# 节点数量: {len(links)}
# Subscription-Userinfo: {userinfo}
"""

    # 【修改点2】修正 Clash 模板里的真实订阅地址，解决 Clash 拉取失败
    clash = f"""mixed-port: 7890
allow-lan: true
mode: rule
log-level: info
external-controller: 127.0.0.1:9090

proxy-providers:
  蓝猫:
    type: http
    url: "https://raw.githubusercontent.com/Luckdog-cook/lanmao-sub/main/bluecat_nodes_base64.txt"
    interval: 3600
    path: ./providers/蓝猫.yaml
    health-check:
      enable: true
      interval: 600
      url: http://www.gstatic.com/generate_204

proxies: []

proxy-groups:
  - name: 🚀 节点选择
    type: select
    use:
      - 蓝猫
    proxies:
      - ♻️ 自动选择
      - DIRECT
  - name: ♻️ 自动选择
    type: url-test
    use:
      - 蓝猫
    url: http://www.gstatic.com/generate_204
    interval: 300

rules:
  - GEOIP,CN,DIRECT
  - MATCH,🚀 节点选择
"""

    targets = [OUT_DIR] + [Path(d) for d in EXTRA_OUT_DIRS]
    for t in targets:
        try:
            t.mkdir(parents=True, exist_ok=True)
            (t / "nodes.txt").write_text(plain, encoding="utf-8")
            # 【修改点3】写入文件时统一命名为 bluecat_nodes_base64.txt
            (t / "bluecat_nodes_base64.txt").write_text(b64, encoding="utf-8")
            (t / "subscription_info.txt").write_text(info, encoding="utf-8")
            (t / "clash.yaml").write_text(clash, encoding="utf-8")
            logger.info("已写入: %s", t)
        except Exception as e:
            logger.warning("写入失败 %s: %s", t, e)

def fetch_subscribe(jwt: str, md5_tok: str) -> bool:
    if not jwt and not md5_tok:
        logger.error("无凭据")
        return False
    gw = get_gateway()
    logger.info("网关: %s", gw)
    st, body = http("GET", gw + "/app/subscribe", headers=headers_for(jwt, md5_tok))
    try:
        j = json.loads(body)
    except Exception:
        logger.error("非 JSON 响应")
        return False
    if j.get("code") != 1:
        logger.error("拉取失败: %s", j.get("message"))
        return False
    links = []
    for s in (j.get("data") or []):
        for n in (s.get("node") or []):
            if isinstance(n, str) and n.strip():
                links.append(n.strip())
    links = filter_and_dedup(links)
    if not links:
        logger.error("无节点")
        return False
    if ENABLE_LATENCY_TEST:
        links = filter_by_latency(links)
        if not links:
            logger.error("延迟测试后无可用节点")
            return False
    write_outputs(links)
    logger.info("成功获取 %d 个节点", len(links))
    return True

def cmd_register(email: str, pwd: str) -> bool:
    gw = get_gateway()
    logger.info("注册 %s", email)
    st, body = http("POST", gw + "/app/register", body={"email": email, "password": pwd}, headers=headers_for())
    try:
        j = json.loads(body)
    except Exception:
        return False
    if j.get("code") == 1 and j.get("data"):
        d = j["data"]
        save_token(d.get("token") or "", d.get("auth_data") or "", email)
        return fetch_subscribe(d.get("auth_data") or "", d.get("token") or "")
    logger.error("注册失败: %s", j.get("message"))
    return False

def cmd_login(email: str, pwd: str) -> bool:
    gw = get_gateway()
    st, body = http("POST", gw + "/app/login", body={"email": email, "password": pwd}, headers=headers_for())
    try:
        j = json.loads(body)
    except Exception:
        return False
    if j.get("code") == 1 and j.get("data"):
        d = j["data"]
        save_token(d.get("token") or "", d.get("auth_data") or "", email)
        return fetch_subscribe(d.get("auth_data") or "", d.get("token") or "")
    return False

# 【修改点4】加入“节点死绝自动换号”逻辑
def cmd_auto(force_new: bool = False) -> bool:
    d = load_token_full()
    md5_tok, jwt, email = d.get("token") or "", d.get("auth") or "", d.get("email") or ""
    if force_new:
        return cmd_register(rand_email(), DEFAULT_PASSWORD)
    if not (jwt or md5_tok):
        return cmd_register(rand_email(), DEFAULT_PASSWORD)
    
    age = token_age_seconds()
    logger.info("当前账号: %s | %s", email or "未知", format_remain())
    
    if is_token_expired():
        logger.info("账号过期，换新号")
        return cmd_register(rand_email(), DEFAULT_PASSWORD)
    
    if not fetch_subscribe(jwt, md5_tok):
        logger.warning("刷新失败，换新号")
        return cmd_register(rand_email(), DEFAULT_PASSWORD)
    
    # 新增判断：如果抓到的节点少于 8 个，强制换号重新抓取
    if os.path.exists(NODES_FILE):
        with open(NODES_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
        valid_lines = [l for l in lines if l.strip()]
        if len(valid_lines) < 8:
            logger.warning("当前账号节点存活极少（%d个），强制换新号重新抓取", len(valid_lines))
            return cmd_register(rand_email(), DEFAULT_PASSWORD)
            
    return True

def cmd_status():
    d = load_token_full()
    if not d:
        print("当前无账号")
        return
    print("=" * 50)
    print("邮箱     :", d.get("email") or "(无)")
    print("创建时间 :", d.get("created_at_str") or "未知")
    print("剩余时间 :", format_remain())
    print("加密     :", "是" if ENCRYPT_KEY else "否")
    print("延迟测试 :", "开启" if ENABLE_LATENCY_TEST else "关闭")
    print("=" * 50)

def main():
    parser = argparse.ArgumentParser(description="蓝猫VPN 最终版")
    parser.add_argument("command", nargs="?", default="auto")
    parser.add_argument("arg1", nargs="?")
    parser.add_argument("arg2", nargs="?")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--no-latency", action="store_true", help="关闭延迟测试")
    args = parser.parse_args()
    global ENABLE_LATENCY_TEST
    if args.no_latency: ENABLE_LATENCY_TEST = False
    setup_logging(args.verbose)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    cmd = (args.command or "auto").lower()
    if cmd in ("auto", ""):
        ok = cmd_auto()
    elif cmd in ("force", "new"):
        ok = cmd_auto(True)
    elif cmd == "sub":
        md5, jwt = load_token()
        ok = fetch_subscribe(jwt, md5)
    elif cmd == "status":
        cmd_status()
        return
    elif cmd == "register":
        ok = cmd_register(args.arg1 or rand_email(), args.arg2 or DEFAULT_PASSWORD)
    else:
        parser.print_help()
        sys.exit(1)
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
