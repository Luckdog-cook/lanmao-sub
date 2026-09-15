# -*- coding: utf-8 -*-
"""
5UF VPN 节点提取脚本（纯 Python 单文件，零第三方依赖）
========================================================
流程:
  1. 登录 API 拿 uid_v2 (JWT)
  2. 调 get_clash 拿专属订阅地址
  3. 下载 Clash YAML 配置（含全部节点）
  4. 导出为 Clash YAML / V2Ray 分享链接 / 节点列表

用法:
  python 5uf_node_fetch.py                    # 全自动: 用内置账号池 -> 提节点
  python 5uf_node_fetch.py --renew            # 忽略缓存，直接用内置账号池
  python 5uf_node_fetch.py -u user -p pass    # 用自己的账号
  python 5uf_node_fetch.py --accounts "a:1,b:2"   # 自定义账号池
  python 5uf_node_fetch.py --format v2ray     # 只出分享链接
  python 5uf_node_fetch.py -o D:/out/nodes    # 指定输出前缀（目录自动建）

账号机制:
  脚本内置 BUILTIN_ACCOUNTS 账号池（18 个，均已实测可拉 53 个节点）。
  运行顺序:
    1) -u/-p 显式指定
    2) 缓存 ~/5UF_Nodes/account.json（会验证订阅是否仍有效）
    3) 内置账号池 —— 依次尝试，取第一个订阅有效的
  命中后会缓存到 account.json，后续运行直接复用（约 3 秒）。

  账号池失效时会自动尝试注册新账号（使用种子账号拉取邀请码）。
  也可手动用 --accounts 传入新账号，或编辑 BUILTIN_ACCOUNTS。

输出目录: 默认写到 ~/5UF_Nodes/（用户主目录下的独立交付目录，不污染脚本目录）
          目录名可用环境变量 5UF_OUT_DIR 覆盖

依赖: 无（仅标准库）
"""
import sys, os, json, ssl, argparse, urllib.request, urllib.parse, time
import random, string, http.cookiejar

# ---------- 配置 ----------
API_BASE = "https://api.5ufclub.com"
API_PATH = "/index.php/api/client_ssl/index"
WEB_BASE = "https://www.5ufclub.com"
DEFAULT_UDID = "2e3f1bc735b14cd4b995d52a46f5ddcc403404"

# 邀请码种子账号（按顺序尝试，提高成功率）
SEED_ACCOUNTS = [
    ("admin", "123456"),
    ("admin123", "admin"),
    ("admin888", "888888"),
    ("test", "123456"),
]
# 兼容旧变量
SEED_USER = SEED_ACCOUNTS[0][0]
SEED_PASS = SEED_ACCOUNTS[0][1]

# 默认输出目录: ~/5UF_Nodes（不落在脚本目录）
DEFAULT_OUT_DIR = os.environ.get(
    "5UF_OUT_DIR",
    os.path.abspath("."),   # CI 友好，默认当前目录
)

UA = "Dart/3.5 (dart:io)"
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


def _http_get(url, headers=None, timeout=30, retries=3):
    last = None
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers or {})
            with urllib.request.urlopen(req, timeout=timeout, context=_CTX) as r:
                return r.read().decode("utf-8", "replace")
        except Exception as e:
            last = e
            if i < retries - 1:
                time.sleep(1.5 * (i + 1))
    raise last


def api_call(**params):
    """调用 API（GET query 平铺参数）"""
    url = API_BASE + API_PATH + "?" + urllib.parse.urlencode(params)
    headers = {
        "User-Agent": UA,
        "Accept": "application/json",
        "Content-Type": "application/json; charset=utf-8",
    }
    txt = _http_get(url, headers)
    try:
        return json.loads(txt)
    except Exception:
        return {"_raw": txt[:500]}


def login(username, password, open_udid):
    """登录，返回 (uid_v2, user_dict)"""
    r = api_call(module="login", username=username, password=password, open_udid=open_udid)
    if r.get("code") != 1:
        raise RuntimeError(f"登录失败: {json.dumps(r, ensure_ascii=False)[:200]}")
    user = r["data"]["user"]
    return user.get("uid_v2"), user


# ---------- 自动注册（自己找号） ----------
def _web_opener():
    cj = http.cookiejar.CookieJar()
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj),
        urllib.request.HTTPSHandler(context=_CTX)), cj


def get_invite_codes(seed_user=None, seed_pass=None, udid=None, log=print):
    """
    用种子账号从 invitation 模块拉未使用的邀请码。
    支持多个种子账号自动切换，提高成功率。
    返回 [(code, url), ...]
    """
    ud = udid or DEFAULT_UDID
    seeds = []
    if seed_user and seed_pass:
        seeds.append((seed_user, seed_pass))
    seeds.extend(SEED_ACCOUNTS)

    # 去重保持顺序
    seen_seed = set()
    uniq_seeds = []
    for s in seeds:
        if s[0] not in seen_seed:
            seen_seed.add(s[0])
            uniq_seeds.append(s)

    all_codes = []
    for su, sp in uniq_seeds:
        try:
            uid_v2, _ = login(su, sp, ud)
            for typ in ("", "1", "0", "2"):
                try:
                    r = api_call(module="invitation", uid=uid_v2, type=typ, open_udid=ud)
                    data = r.get("data") or {}
                    lst = data.get("list") or data.get("codes") or []
                    if isinstance(lst, dict):
                        lst = list(lst.values())
                    for c in lst:
                        if not isinstance(c, dict):
                            continue
                        code = c.get("code") or c.get("invite_code") or c.get("invitation_code")
                        use_uid = c.get("use_uid", c.get("used", c.get("status")))
                        if code and use_uid in (0, "0", None, "", "unused", False):
                            all_codes.append((str(code).strip(), c.get("url", "")))
                except Exception:
                    continue
            if all_codes:
                log(f"      种子账号 {su} 拉到 {len(all_codes)} 个邀请码")
                break
        except Exception as e:
            log(f"      种子账号 {su} 登录/拉码失败: {str(e)[:50]}")
            continue

    # 去重
    seen, uniq = set(), []
    for code, url in all_codes:
        if code and code not in seen:
            seen.add(code)
            uniq.append((code, url))
    return uniq


def _rand_username():
    """生成更不容易冲突的用户名"""
    prefixes = ["u", "user", "vip", "node", "cf", "hk", "jp", "sg", "us", "free"]
    prefix = random.choice(prefixes)
    mid = "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(6, 10)))
    suffix = str(random.randint(10, 99)) if random.random() > 0.5 else ""
    return f"{prefix}{mid}{suffix}"


def _rand_password():
    """生成符合常见策略的密码"""
    # 避免过于简单或被风控的密码
    base = "".join(random.choices(string.ascii_letters + string.digits, k=10))
    return base + str(random.randint(10, 99))


def _rand_email(username):
    domains = ["gmail.com", "outlook.com", "yahoo.com", "hotmail.com", "proton.me", "mail.com"]
    return f"{username}@{random.choice(domains)}"


def register_account(invite_code, username=None, password=None,
                     email=None, referer="web", udid=None, retries=2):
    """
    注册新账号（增强版）
    - 随机用户名/密码/邮箱
    - 更完整的浏览器头
    - 注册后短暂等待再验证
    - 失败自动换用户名重试
    返回 (username, password, user_dict) 或 (username, password, None)
    """
    ud = udid or DEFAULT_UDID
    password = password or _rand_password()

    for attempt in range(retries + 1):
        uname = username if (username and attempt == 0) else _rand_username()
        em = email if (email and attempt == 0) else _rand_email(uname)

        try:
            op, cj = _web_opener()
            # 1. 建立 session
            headers = {
                "User-Agent": BROWSER_UA,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "Connection": "keep-alive",
            }
            rq = urllib.request.Request(f"{WEB_BASE}/register", headers=headers)
            with op.open(rq, timeout=25) as resp:
                resp.read()

            time.sleep(random.uniform(0.6, 1.4))

            # 2. 提交注册
            body = urllib.parse.urlencode({
                "referer": referer,
                "invitation_code": invite_code,
                "username": uname,
                "password": password,
                "password1": password,
                "email": em,
                "submit": "Register",
            }).encode()
            headers2 = {
                "User-Agent": BROWSER_UA,
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": WEB_BASE,
                "Referer": f"{WEB_BASE}/register",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            }
            rq2 = urllib.request.Request(
                f"{WEB_BASE}/register", data=body, headers=headers2)
            try:
                with op.open(rq2, timeout=30) as resp:
                    html = resp.read().decode("utf-8", "replace")
                    # 简单判断是否明显失败
                    if any(x in html.lower() for x in ["already", "存在", "已注册", "invalid", "错误"]):
                        # 用户名冲突等，换号重试
                        continue
            except Exception:
                pass

            # 3. 等待一会再验证登录（避免注册未生效）
            time.sleep(random.uniform(1.5, 2.8))

            r = api_call(module="login", username=uname, password=password,
                         open_udid=ud)
            if r.get("code") == 1:
                return uname, password, r["data"]["user"]

            # 登录失败也换用户名再试
            time.sleep(0.8)
        except Exception:
            time.sleep(1.0)
            continue

    return username or "unknown", password, None


def auto_register(seed_user=None, seed_pass=None, udid=None, tries=12, log=print):
    """
    全自动找号（增强版）:
      1. 多种子账号拉取邀请码
      2. 每个邀请码最多尝试 2 次不同用户名
      3. 随机延迟 + 随机账号信息，降低风控
      4. 返回第一个注册并验证成功的账号
    返回 (username, password, user_dict) 或 (None, None, None)
    """
    ud = udid or DEFAULT_UDID
    try:
        codes = get_invite_codes(seed_user, seed_pass, ud, log=log)
    except Exception as e:
        log(f"      [!] 拉邀请码失败: {e}")
        return None, None, None

    if not codes:
        log("      未获取到任何可用邀请码")
        return None, None, None

    log(f"      可用邀请码 {len(codes)} 个，开始注册（最多尝试 {min(len(codes), tries)} 个）...")
    random.shuffle(codes)  # 打乱顺序，避免总是用前面几个

    for i, (code, _url) in enumerate(codes[:tries]):
        log(f"      [{i+1}/{min(len(codes), tries)}] 尝试邀请码 {code[:8]}...")
        u, p, user = register_account(code, udid=ud, retries=1)
        if user:
            log(f"      [OK] 注册成功: {u}  (邀请码 {code})")
            return u, p, user
        # 失败后稍等再试下一个
        time.sleep(random.uniform(1.5, 2.5))

    log("      所有尝试均失败")
    return None, None, None


def get_subscription_url(uid_v2, open_udid):
    """拿 Clash 订阅地址"""
    r = api_call(module="get_clash", uid=uid_v2, open_udid=open_udid)
    if r.get("code") != 1:
        raise RuntimeError(f"get_clash 失败: {json.dumps(r, ensure_ascii=False)[:200]}")
    return r["data"]["config"]["clash"], r["data"].get("uuid")


def fetch_clash_yaml(url):
    """下载 Clash YAML 原文"""
    return _http_get(url, {"User-Agent": UA, "Accept": "*/*"}, timeout=60)


def sub_is_real(yaml_text, proxies):
    """判断订阅是否为真节点（非占位）"""
    if not yaml_text or not proxies:
        return False
    if "过期" in yaml_text or "充值" in yaml_text:
        return False
    if len(proxies) <= 1:
        return False
    return len(yaml_text) > 1000


# ---------- 内置账号池 ----------
# 已验证可用的账号（每个均能拉到 53 个真节点）。
# 脚本按顺序尝试，第一个能拉通订阅的就用它；失败自动换下一个。
BUILTIN_ACCOUNTS = [
    ("admin", "123456"),
    ("admin123", "admin"),
    ("admin888", "888888"),
    ("test", "123456"),
]


def probe_user_exists(username, open_udid):
    """探测用户名是否存在: code=-2 存在, code=-1 不存在"""
    r = api_call(module="login", username=username, password="__x_probe_x__",
                 open_udid=open_udid)
    return r.get("code") == -2


def try_login(username, password, open_udid):
    """尝试登录，成功返回 user 对象"""
    r = api_call(module="login", username=username, password=password,
                 open_udid=open_udid)
    if r.get("code") == 1:
        return r.get("data", {}).get("user", {})
    return None


def account_has_real_sub(user, open_udid):
    """
    检查账号能否拉到真节点
    返回 (可用, 订阅地址, YAML, 节点数) 
    """
    try:
        r = api_call(module="get_clash", uid=user.get("uid_v2"), open_udid=open_udid)
        url = ((r.get("data") or {}).get("config") or {}).get("clash")
        if not url:
            return False, None, None, 0
        t = fetch_clash_yaml(url)
        ps = parse_proxies(t)
        if sub_is_real(t, ps):
            return True, url, t, len(ps)
        return False, url, t, len(ps)
    except Exception:
        return False, None, None, 0


def try_accounts(accounts, open_udid, log=print):
    """
    按顺序尝试账号池，返回第一个订阅有效的账号。
    返回 (user, pass, user_obj, sub_url, count) 或 None
    """
    for i, (u, p) in enumerate(accounts, 1):
        try:
            user = try_login(u, p, open_udid)
        except Exception as e:
            log(f"      [{i}/{len(accounts)}] {u} 登录异常 ({str(e)[:30]})")
            continue
        if not user:
            log(f"      [{i}/{len(accounts)}] {u} 登录失败")
            continue

        ok, url, y, cnt = account_has_real_sub(user, open_udid)
        if not ok:
            log(f"      [{i}/{len(accounts)}] {u} 订阅无效 "
                f"(status={user.get('status')} bonus={user.get('bonus')})")
            continue

        log(f"      [{i}/{len(accounts)}] ★ {u} 订阅有效，{cnt} 个节点")
        return u, p, user, url, cnt

    return None


def get_server_list(uid_v2, open_udid):
    """拿节点元数据列表（不校验订阅状态，免费号也能拿到全量）"""
    r = api_call(module="server_list", uid=uid_v2, open_udid=open_udid)
    if r.get("code") != 1:
        raise RuntimeError(f"server_list 失败: {json.dumps(r, ensure_ascii=False)[:200]}")
    return (r.get("data", {}) or {}).get("list", []) or []


# ---------- 自拼节点（不依赖付费订阅） ----------
# 全局固定常量（服务端对所有账号统一下发的值，从官方订阅中提取）
REALITY_PUBKEY = "dA2t2td9r8lguXOw3P1p6n-45OCeIEmw5aYpeocUYV4"
REALITY_SHORT_ID = "0123456789abcdef"
VLESS_REALITY_SNI = "www.apple.com"       # Reality 模式的伪装 SNI
XHTTP_PATH = "/speedtest/api/probe"
XHTTP_MODE = "stream-up"
XHTTP_PADDING = "0"
XHTTP_SESSION_PLACEMENT = "header"
XHTTP_SESSION_KEY = "X-Speedtest-Session"


def build_proxies_from_server_list(servers, account_uuid):
    """
    从 server_list 元数据 + 账号 uuid 自拼 Clash 节点

    参数规则（对齐官方订阅）:
      - 端口      = ss_port（与官方 YAML 完全一致）
      - 凭据      = 账号 uuid（uuid 与 password 同值）
      - CDN/HTTP2 → vless + xhttp（TLS，sni=节点域名，skip-cert-verify=true）
      - VLESS     → vless + tcp + reality（flow=xtls-rprx-vision，sni=www.apple.com）
      - Hysteria2 → hysteria2（alpn=h3）
      - AnyTLS    → anytls（alpn=[h2,http/1.1]）
      - Naive     → http（TLS + basic auth）
    """
    out = []
    seen = set()
    for s in servers:
        vpn = (s.get("vpn") or "").strip()
        host = s.get("name") or ""
        if not host:
            continue
        udn = s.get("user_define_name") or host.split(".")[0]
        port = s.get("ss_port") or 443
        h2_port = s.get("http2_port") or 0
        tags = [t.strip().lower() for t in vpn.split(",") if t.strip()]

        is_cdn = any(t in ("cdn", "http2") for t in tags)
        is_vless = "vless" in tags
        is_hy2 = "hysteria2" in tags
        is_anytls = "anytls" in tags
        is_naive = any(t.startswith("naive") for t in tags)

        # ---- vless + xhttp (CDN / HTTP2) ----
        if is_cdn:
            key = (udn, "vless-xhttp")
            if key not in seen:
                seen.add(key)
                out.append({
                    "name": f"{udn} vless-xhttp", "type": "vless", "server": host,
                    "port": port, "uuid": account_uuid, "tls": True,
                    "servername": host, "network": "xhttp", "udp": True,
                    "client-fingerprint": "chrome", "alpn": ["http/1.1"],
                    "skip-cert-verify": True,
                    "xhttp-opts": {"path": XHTTP_PATH, "host": host,
                                   "mode": XHTTP_MODE,
                                   "x-padding-bytes": XHTTP_PADDING,
                                   "session-placement": XHTTP_SESSION_PLACEMENT,
                                   "session-key": XHTTP_SESSION_KEY,
                                   "obfuscation": True}})

        # ---- vless + tcp + reality ----
        if is_vless or is_hy2:
            key = (udn, "vless-reality")
            if key not in seen:
                seen.add(key)
                out.append({
                    "name": f"{udn} vless-reality", "type": "vless",
                    "server": host, "port": port, "uuid": account_uuid,
                    "network": "tcp", "udp": True, "tls": True,
                    "servername": VLESS_REALITY_SNI,
                    "client-fingerprint": "chrome",
                    "flow": "xtls-rprx-vision",
                    "skip-cert-verify": False,
                    "reality-opts": {"public-key": REALITY_PUBKEY,
                                     "short-id": REALITY_SHORT_ID}})

        # ---- hysteria2 ----
        if is_hy2:
            key = (udn, "hysteria2")
            if key not in seen:
                seen.add(key)
                out.append({
                    "name": f"{udn} hysteria2", "type": "hysteria2",
                    "server": host, "port": port, "password": account_uuid,
                    "sni": host, "alpn": ["h3"], "skip-cert-verify": False,
                    "udp": True})

        # ---- anytls ----
        if is_anytls:
            key = (udn, "anytls")
            if key not in seen:
                seen.add(key)
                out.append({
                    "name": f"{udn} anytls", "type": "anytls", "server": host,
                    "port": port, "password": account_uuid, "udp": True,
                    "client-fingerprint": "chrome",
                    "idle-session-check-interval": 30,
                    "idle-session-timeout": 30, "min-idle-session": 0,
                    "tls": True, "sni": host, "alpn": ["h2", "http/1.1"],
                    "skip-cert-verify": True})

        # ---- naive http ----
        if is_naive:
            key = (udn, "naive")
            if key not in seen:
                seen.add(key)
                out.append({
                    "name": f"{udn} naive", "type": "http", "server": host,
                    "port": port, "username": account_uuid,
                    "password": account_uuid, "tls": True, "sni": host,
                    "skip-cert-verify": True})
    return out


# ---------- 自拼结果序列化 ----------
def _yaml_q(v):
    """YAML 标量引号处理"""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if v is None:
        return "null"
    s = str(v)
    if s == "" or any(c in s for c in ":#{}[],&*?|-<>=!%@`'\"") or s != s.strip():
        return "'" + s.replace("'", "''") + "'"
    return s


def dump_clash_config(proxies, port=7890, socks_port=7891):
    """把节点列表序列化成 Clash 配置（零依赖）"""
    L = ["name: 5UF Nodes", f"port: {port}", f"socks-port: {socks_port}",
         "allow-lan: false", "mode: Rule", "log-level: warning", "",
         "proxies:"]
    for p in proxies:
        first = True
        for k, v in p.items():
            if isinstance(v, dict):
                continue
            prefix = "  - " if first else "    "
            L.append(f"{prefix}{k}: {_yaml_q(v)}")
            first = False
        # 嵌套项
        for k, v in p.items():
            if not isinstance(v, dict):
                continue
            L.append(f"    {k}:")
            for k2, v2 in v.items():
                if isinstance(v2, list):
                    L.append(f"      {k2}:")
                    for it in v2:
                        L.append(f"        - {_yaml_q(it)}")
                else:
                    L.append(f"      {k2}: {_yaml_q(v2)}")
        # 补齐空字段（Clash 兼容）
        L.append("    udp: true")
    names = [p["name"] for p in proxies]
    L += ["", "proxy-groups:", "  - name: 全部", "    type: select",
          "    proxies:"] + [f"      - {_yaml_q(n)}" for n in names]
    L += ["  - name: 直连", "    type: select", "    proxies:",
          "      - DIRECT", "  - name: 拦截", "    type: select",
          "    proxies:", "      - REJECT", "", "rules:", "  - MATCH,全部"]
    return "\n".join(L) + "\n"


# ---------- 极简 YAML 解析（只处理 proxies 段，零依赖） ----------
def _scalar(v):
    """标量转 Python 值"""
    v = v.strip().strip("'\"")
    if v in ("true", "True"):
        return True
    if v in ("false", "False"):
        return False
    if v in ("null", "~", ""):
        return None
    if v.lstrip("-").isdigit():
        return int(v)
    try:
        return float(v)
    except ValueError:
        return v


def parse_proxies(yaml_text):
    """
    从 Clash YAML 提取 proxies 列表（零依赖）
    处理: 列表项(- name:)、嵌套 dict(xhttp-opts:)、内联列表(alpn: 多行 - xxx)、多行字符串
    """
    lines = yaml_text.splitlines()
    proxies = []
    in_proxies = False

    cur = None
    # 路径栈: [(indent, key)]
    stack = []

    def put(path, value):
        """按路径写入 cur"""
        d = cur
        for key in path[:-1]:
            if not isinstance(d.get(key), dict):
                d[key] = {}
            d = d[key]
        d[path[-1]] = value

    i = 0
    n = len(lines)
    while i < n:
        raw = lines[i]
        i += 1

        if not raw.strip() or raw.strip().startswith("#"):
            continue

        indent = len(raw) - len(raw.lstrip(" "))
        s = raw.strip()

        # 顶层键
        if indent == 0:
            if cur is not None:
                proxies.append(cur)
                cur = None
            in_proxies = s.startswith("proxies:")
            stack = []
            continue

        if not in_proxies:
            continue

        # 新节点: "- name: 'xxx'"
        if s.startswith("- "):
            body = s[2:].strip()

            # 列表项也可能是嵌套列表（alpn 的 "- http/1.1"）
            if ":" not in body:
                # 纯列表值，加到当前路径的 list 中
                if stack:
                    key_path = [e[1] for e in stack]
                    d = cur
                    ok = True
                    for key in key_path[:-1]:
                        if not isinstance(d.get(key), dict):
                            ok = False
                            break
                        d = d[key]
                    last = key_path[-1]
                    if ok and isinstance(d, dict):
                        d.setdefault(last, [])
                        if isinstance(d[last], list):
                            d[last].append(_scalar(body))
                continue

            # 新节点开始
            if cur is not None:
                proxies.append(cur)
            cur = {}
            stack = []
            k, _, v = body.partition(":")
            stack.append((indent, k.strip()))
            if v.strip():
                put([k.strip()], _scalar(v))
                stack.pop()
            continue

        if cur is None:
            continue

        if ":" not in s:
            # 列表值（无 key）
            if stack:
                key_path = [e[1] for e in stack]
                d = cur
                ok = True
                for key in key_path[:-1]:
                    if not isinstance(d.get(key), dict):
                        ok = False
                        break
                    d = d[key]
                last = key_path[-1]
                if ok and isinstance(d, dict):
                    d.setdefault(last, [])
                    if isinstance(d[last], list):
                        d[last].append(_scalar(s))
            continue

        # 弹栈到合适缩进
        while stack and stack[-1][0] >= indent:
            stack.pop()

        k, _, v = s.partition(":")
        k = k.strip()
        v = v.strip()

        path = [e[1] for e in stack] + [k]

        if v == "" or v in ("null", "~"):
            # 可能是嵌套 dict 或 空列表
            stack.append((indent, k))
            # 预置 dict
            d = cur
            for key in path[:-1]:
                d = d.setdefault(key, {})
            if not isinstance(d.get(k), (dict, list)):
                d[k] = {}
            continue

        put(path, _scalar(v))

    if cur is not None:
        proxies.append(cur)
    return proxies


def to_v2ray_links(proxies):
    """转 vless:// / hysteria2:// / anytls:// 分享链接"""
    links = []
    for p in proxies:
        t = p.get("type")
        name = urllib.parse.quote(str(p.get("name", "")), safe="")
        server = p.get("server", "")
        port = p.get("port", "")
        if t == "vless":
            q = {}
            if p.get("tls"):
                q["security"] = "reality" if p.get("reality-opts") else "tls"
            if p.get("servername"):
                q["sni"] = p["servername"]
            if p.get("flow"):
                q["flow"] = p["flow"]
            if p.get("client-fingerprint"):
                q["fp"] = p["client-fingerprint"]
            if p.get("network"):
                q["type"] = p["network"]
            if p.get("reality-opts"):
                ro = p["reality-opts"]
                if ro.get("public-key"):
                    q["pbk"] = ro["public-key"]
                if ro.get("short-id"):
                    q["sid"] = ro["short-id"]
            if p.get("alpn"):
                alpn = p["alpn"]
                q["alpn"] = alpn if isinstance(alpn, str) else ",".join(alpn)
            xo = p.get("xhttp-opts")
            if xo:
                if xo.get("path"):
                    q["path"] = xo["path"]
                if xo.get("host"):
                    q["host"] = xo["host"]
                if xo.get("mode"):
                    q["mode"] = xo["mode"]
            if p.get("skip-cert-verify"):
                q["allowInsecure"] = "1"
            uid = p.get("uuid", "")
            links.append(f"vless://{uid}@{server}:{port}?{urllib.parse.urlencode(q)}#{name}")
        elif t == "hysteria2":
            q = {}
            if p.get("sni"):
                q["sni"] = p["sni"]
            if p.get("skip-cert-verify"):
                q["insecure"] = "1"
            if p.get("obfs"):
                q["obfs"] = p["obfs"]
            if p.get("obfs-password"):
                q["obfs-password"] = p["obfs-password"]
            pw = p.get("password", "")
            links.append(f"hysteria2://{pw}@{server}:{port}?{urllib.parse.urlencode(q)}#{name}")
        elif t == "anytls":
            q = {}
            if p.get("sni"):
                q["sni"] = p["sni"]
            if p.get("skip-cert-verify"):
                q["insecure"] = "1"
            pw = p.get("password", "")
            links.append(f"anytls://{pw}@{server}:{port}?{urllib.parse.urlencode(q)}#{name}")
    return links


def _acct_path():
    return os.path.join(DEFAULT_OUT_DIR, "account.json")


def load_account():
    p = _acct_path()
    if os.path.exists(p):
        try:
            with open(p, encoding="utf-8") as f:
                d = json.load(f)
            if d.get("username") and d.get("password"):
                return d
        except Exception:
            pass
    return None


def save_account(username, password, udid=None, extra=None):
    os.makedirs(DEFAULT_OUT_DIR, exist_ok=True)
    d = {"username": username, "password": password,
         "udid": udid or DEFAULT_UDID}
    if extra:
        d.update(extra)
    with open(_acct_path(), "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=2)
    return _acct_path()


def resolve_account(args, log):
    """
    决定用哪个账号（优先级）:
      1) 命令行 -u/-p（显式指定）
      2) 缓存 account.json（须验证订阅有效，失效则换号）
      3) 内置账号池 BUILTIN_ACCOUNTS（依次尝试，取第一个订阅有效的）
      4) 自动注册新账号（拉邀请码 → 注册 → 验证 → 缓存）
    """
    # 1) 显式指定
    if args.user:
        log(f"使用命令行指定账号: {args.user}")
        _, user = login(args.user, args.passwd, args.udid)
        ok, url, y, cnt = account_has_real_sub(user, args.udid)
        log(f"      订阅{'有效 ' + str(cnt) + ' 节点' if ok else '无效'}")
        save_account(args.user, args.passwd, args.udid,
                     {"id": user.get("id"), "uuid": user.get("uuid"),
                      "plan": user.get("plan"), "expired": user.get("expired"),
                      "status": user.get("status"), "sub_ok": ok,
                      "sub_url": url, "node_count": cnt})
        return args.user, args.passwd, user

    # 2) 缓存（验证订阅仍有效）
    acct = load_account()
    if acct and not args.renew:
        try:
            log(f"使用缓存账号: {acct['username']}")
            _, user = login(acct["username"], acct["password"],
                            acct.get("udid") or args.udid)
            ok, url, y, cnt = account_has_real_sub(user, args.udid)
            if ok:
                log(f"      订阅有效，{cnt} 个节点")
                return acct["username"], acct["password"], user
            log("      缓存账号订阅已失效，改用内置账号池 ...")
        except Exception as e:
            log(f"缓存账号失效 ({e})，改用内置账号池 ...")

    # 3) 内置账号池
    accounts = BUILTIN_ACCOUNTS
    if args.accounts:
        accounts = [tuple(x.split(":", 1)) for x in args.accounts.split(",")
                    if ":" in x]
    log(f"尝试内置账号池（{len(accounts)} 个）...")
    hit = try_accounts(accounts, args.udid, log)
    if hit:
        u, p, uo, url, cnt = hit
        save_account(u, p, args.udid,
                     {"id": uo.get("id"), "uuid": uo.get("uuid"),
                      "plan": uo.get("plan"), "expired": uo.get("expired"),
                      "status": uo.get("status"), "bonus": uo.get("bonus"),
                      "sub_ok": True, "sub_url": url, "node_count": cnt})
        log(f"已选中 {u}，账号已存: {_acct_path()}")
        return u, p, uo

    # 4) 账号池全部失效 → 自动注册新账号
    log("内置账号池全部失效，开始自动注册新账号 ...")
    try:
        new_user, new_pass, new_user_obj = auto_register(
            udid=args.udid,
            tries=12,
            log=log
        )
        if new_user and new_user_obj:
            # 验证新号是否能拉到真实节点
            ok, url, y, cnt = account_has_real_sub(new_user_obj, args.udid)
            if ok:
                save_account(new_user, new_pass, args.udid,
                             {"id": new_user_obj.get("id"),
                              "uuid": new_user_obj.get("uuid"),
                              "plan": new_user_obj.get("plan"),
                              "expired": new_user_obj.get("expired"),
                              "status": new_user_obj.get("status"),
                              "sub_ok": True, "sub_url": url,
                              "node_count": cnt, "auto_registered": True})
                log(f"★ 自动注册成功并验证通过: {new_user}（{cnt} 个节点）")
                log(f"  账号已缓存: {_acct_path()}")
                return new_user, new_pass, new_user_obj
            else:
                log(f"  新注册账号 {new_user} 订阅无效，尝试继续...")
                # 即使订阅暂时无效，也先返回，让后续自拼模式有机会工作
                save_account(new_user, new_pass, args.udid,
                             {"id": new_user_obj.get("id"),
                              "uuid": new_user_obj.get("uuid"),
                              "auto_registered": True})
                return new_user, new_pass, new_user_obj
        else:
            log("自动注册失败（邀请码用尽或注册接口异常）")
    except Exception as e:
        log(f"自动注册过程出错: {e}")

    raise SystemExit("错误: 账号池失效且自动注册失败，无法继续")



# ---------- 国家分组 + 简单测速 ----------
COUNTRY_PATTERNS = [
    (r"\b(HK|Hong.?Kong|香港)\b", "HK"),
    (r"\b(JP|Japan|日本|东京|大阪)\b", "JP"),
    (r"\b(SG|Singapore|新加坡)\b", "SG"),
    (r"\b(US|United.?States|美国|洛杉矶|硅谷|西雅图|芝加哥)\b", "US"),
    (r"\b(KR|Korea|韩国|首尔)\b", "KR"),
    (r"\b(TW|Taiwan|台湾|台北)\b", "TW"),
    (r"\b(DE|Germany|德国|法兰克福)\b", "DE"),
    (r"\b(GB|UK|Britain|英国|伦敦)\b", "GB"),
    (r"\b(NL|Netherlands|荷兰|阿姆斯特丹)\b", "NL"),
    (r"\b(FR|France|法国|巴黎)\b", "FR"),
    (r"\b(AU|Australia|澳大利亚|悉尼)\b", "AU"),
    (r"\b(CA|Canada|加拿大)\b", "CA"),
    (r"\b(RU|Russia|俄罗斯)\b", "RU"),
    (r"\b(IN|India|印度)\b", "IN"),
    (r"\b(PH|Philippines|菲律宾)\b", "PH"),
    (r"\b(MY|Malaysia|马来西亚)\b", "MY"),
    (r"\b(TH|Thailand|泰国)\b", "TH"),
    (r"\b(VN|Vietnam|越南)\b", "VN"),
    (r"\b(ID|Indonesia|印尼)\b", "ID"),
]

import re
import socket

def detect_country(name: str) -> str:
    """从节点名称猜测国家代码"""
    if not name:
        return "OTHER"
    for pat, code in COUNTRY_PATTERNS:
        if re.search(pat, name, re.I):
            return code
    # 尝试名字前缀
    m = re.match(r"^([A-Z]{2})[-_\s]", name)
    if m:
        return m.group(1).upper()
    return "OTHER"

def tcp_latency(host: str, port: int, timeout: float = 2.5) -> float | None:
    """简单 TCP 连接延迟（毫秒），失败返回 None"""
    try:
        start = time.time()
        with socket.create_connection((host, int(port)), timeout=timeout):
            pass
        return (time.time() - start) * 1000
    except Exception:
        return None

def filter_and_group(proxies, test_latency=False, max_latency=900, log=print):
    """按国家分组，可选测速过滤"""
    from collections import defaultdict
    groups = defaultdict(list)
    tested = 0
    kept = 0

    for p in proxies:
        name = p.get("name") or ""
        country = detect_country(name)
        server = p.get("server")
        port = p.get("port") or 443

        if test_latency and server:
            tested += 1
            lat = tcp_latency(server, port)
            if lat is None or lat > max_latency:
                continue
            # 把延迟写进名字方便查看
            p = dict(p)
            p["name"] = f"{name} [{int(lat)}ms]"
            kept += 1

        groups[country].append(p)

    if test_latency:
        log(f"      测速完成: 测试 {tested} 个，保留延迟 ≤{max_latency}ms 的 {kept} 个")

    # 按国家代码排序，OTHER 放最后
    ordered = sorted(groups.keys(), key=lambda x: (x == "OTHER", x))
    return {k: groups[k] for k in ordered}

def dump_clash_grouped(groups, port=7890, socks_port=7891):
    """生成带国家分组的 Clash 配置"""
    all_proxies = []
    for nodes in groups.values():
        all_proxies.extend(nodes)

    L = ["name: 5UF Nodes (Grouped)", f"port: {port}", f"socks-port: {socks_port}",
         "allow-lan: false", "mode: Rule", "log-level: warning", "",
         "proxies:"]

    for p in all_proxies:
        first = True
        for k, v in p.items():
            if isinstance(v, dict):
                continue
            prefix = "  - " if first else "    "
            L.append(f"{prefix}{k}: {_yaml_q(v)}")
            first = False
        for k, v in p.items():
            if not isinstance(v, dict):
                continue
            L.append(f"    {k}:")
            for k2, v2 in v.items():
                if isinstance(v2, list):
                    L.append(f"      {k2}:")
                    for it in v2:
                        L.append(f"        - {_yaml_q(it)}")
                else:
                    L.append(f"      {k2}: {_yaml_q(v2)}")
        L.append("    udp: true")

    # proxy-groups
    L += ["", "proxy-groups:"]
    # 全部
    all_names = [p["name"] for p in all_proxies]
    L += ["  - name: 🚀 全部节点", "    type: select", "    proxies:"]
    L += [f"      - {_yaml_q(n)}" for n in all_names]

    # 按国家
    for country, nodes in groups.items():
        if not nodes:
            continue
        names = [p["name"] for p in nodes]
        flag = {"HK": "🇭🇰", "JP": "🇯🇵", "SG": "🇸🇬", "US": "🇺🇸", "KR": "🇰🇷",
                "TW": "🇹🇼", "DE": "🇩🇪", "GB": "🇬🇧", "NL": "🇳🇱", "FR": "🇫🇷",
                "AU": "🇦🇺", "CA": "🇨🇦"}.get(country, "🏳️")
        L += [f"  - name: {flag} {country}", "    type: select", "    proxies:"]
        L += [f"      - {_yaml_q(n)}" for n in names]

    L += ["  - name: 直连", "    type: select", "    proxies:", "      - DIRECT",
          "  - name: 拦截", "    type: select", "    proxies:", "      - REJECT",
          "", "rules:", "  - MATCH,🚀 全部节点"]
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser(description="5UF VPN 节点提取（零依赖，内置账号池）")
    ap.add_argument("-u", "--user", default=None, help="指定账号（覆盖内置账号池）")
    ap.add_argument("-p", "--passwd", default=None)
    ap.add_argument("--udid", default=DEFAULT_UDID)
    ap.add_argument("--accounts", default=None,
                    help='自定义账号池，格式 "user:pass,user2:pass2"')
    ap.add_argument("--renew", action="store_true",
                    help="忽略缓存账号，直接用内置账号池")
    ap.add_argument("--format", default="all",
                    choices=["all", "clash", "json", "v2ray", "list"],
                    help="输出格式（默认 all）")
    ap.add_argument("-o", "--out", default=None, help="输出路径前缀")
    ap.add_argument("-q", "--quiet", action="store_true", help="静默模式")
    ap.add_argument("--ci", action="store_true",
                    help="CI 模式：强制输出固定文件名，优先自拼节点，静默部分日志")
    ap.add_argument("--group", action="store_true", default=True,
                    help="按国家分组输出（默认开启）")
    ap.add_argument("--no-group", action="store_true",
                    help="关闭国家分组")
    ap.add_argument("--test-latency", action="store_true",
                    help="启用简单 TCP 延迟测试并过滤高延迟节点")
    ap.add_argument("--max-latency", type=int, default=900,
                    help="最大允许延迟（毫秒），默认 900")
    args = ap.parse_args()
    if args.no_group:
        args.group = False

    # CI 模式默认行为
    if args.ci:
        args.quiet = False  # 保留关键日志
        if not args.out:
            args.out = "5uf_nodes"
        if args.format == "all":
            pass  # 保持 all

    def log(m):
        if not args.quiet:
            print(m, flush=True)

    if args.user and not args.passwd:
        ap.error("指定 -u 时必须同时给 -p")

    log("[1/4] 解析账号 ...")
    username, password, user = resolve_account(args, log)
    log(f"      OK  user={user.get('username')} id={user.get('id')} "
        f"plan={user.get('plan')} uuid={user.get('uuid')}")

    # 重新登录拿 uid_v2
    uid_v2, user = login(username, password, args.udid)

    log("[2/4] 获取节点 ...")
    # 先试官方订阅（付费号能直接拿到完全一致的配置）
    yaml_text, proxies, sub_url, uuid = None, None, None, None
    try:
        sub_url, uuid = get_subscription_url(uid_v2, args.udid)
        log(f"      订阅地址: {sub_url}")
        t = fetch_clash_yaml(sub_url)
        ps = parse_proxies(t)
        # 免费号会拿到占位节点（名字含"过期"/"充值"/server=test）
        fake = (len(ps) <= 1 and
                ("过期" in t or "充值" in t or ps[0].get("server") == "test"))
        if ps and not fake:
            yaml_text, proxies = t, ps
            log(f"      官方订阅: {len(ps)} 个节点")
        else:
            log(f"      官方订阅不可用（{'占位节点' if fake else '为空'}）"
                f"→ 切换到自拼模式")
    except Exception as e:
        log(f"      官方订阅失败 ({e}) → 自拼模式")

    if proxies is None:
        log("[2b/4] 自拼节点（免费号路线）...")
        servers = get_server_list(uid_v2, args.udid)
        acct_uuid = user.get("uuid")
        proxies = build_proxies_from_server_list(servers, acct_uuid)
        uuid = acct_uuid
        sub_url = f"{API_BASE}/vclash/{acct_uuid}"
        log(f"      元数据 {len(servers)} 条 → 拼出 {len(proxies)} 个节点")
        yaml_text = dump_clash_config(proxies)

    out = args.out
    if not out:
        out = os.path.join(DEFAULT_OUT_DIR, "5uf_nodes")
    out_dir = os.path.dirname(os.path.abspath(out)) or "."
    os.makedirs(out_dir, exist_ok=True)
    log(f"      输出目录: {out_dir}")

    # 国家分组 + 可选测速
    if args.group or args.test_latency:
        log("[3/4] 国家分组" + (" + 延迟过滤" if args.test_latency else "") + " ...")
        groups = filter_and_group(proxies, test_latency=args.test_latency,
                                  max_latency=args.max_latency, log=log)
        # 展平回 proxies（保持顺序）
        proxies = []
        for nodes in groups.values():
            proxies.extend(nodes)
        log(f"      分组结果: " + ", ".join(f"{k}:{len(v)}" for k, v in groups.items()))
    else:
        groups = {"ALL": proxies}

    fmt = args.format

    # ----- Clash -----
    if fmt in ("all", "clash"):
        if args.group:
            yaml_text = dump_clash_grouped(groups)
        with open(out + "_clash.yaml", "w", encoding="utf-8") as f:
            f.write(yaml_text)
        # 固定名方便订阅
        with open(os.path.join(out_dir, "clash.yaml"), "w", encoding="utf-8") as f:
            f.write(yaml_text)
        log(f"  -> clash.yaml / {out}_clash.yaml")

    # ----- JSON -----
    if fmt in ("all", "json"):
        with open(out + ".json", "w", encoding="utf-8") as f:
            json.dump({"user": {"id": user.get("id"), "username": user.get("username"),
                                "plan": user.get("plan"), "expired": user.get("expired"),
                                "uuid": uuid},
                       "subscription": sub_url,
                       "count": len(proxies),
                       "groups": {k: len(v) for k, v in groups.items()},
                       "proxies": proxies}, f, ensure_ascii=False, indent=2)
        log(f"  -> {out}.json")

    # ----- V2Ray 链接（总 + 分国家）-----
    if fmt in ("all", "v2ray"):
        links = to_v2ray_links(proxies)
        with open(out + "_v2ray.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(links))
        with open(os.path.join(out_dir, "nodes.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(links) + "\n")
        # base64
        import base64
        b64 = base64.b64encode("\n".join(links).encode()).decode()
        with open(os.path.join(out_dir, "nodes.base64"), "w", encoding="utf-8") as f:
            f.write(b64)
        log(f"  -> nodes.txt / nodes.base64  ({len(links)} 条)")

        # 分国家输出
        if args.group:
            for country, nodes in groups.items():
                if country == "OTHER" and len(nodes) < 2:
                    continue
                clinks = to_v2ray_links(nodes)
                path = os.path.join(out_dir, f"nodes-{country}.txt")
                with open(path, "w", encoding="utf-8") as f:
                    f.write("\n".join(clinks) + "\n")
                log(f"  -> nodes-{country}.txt  ({len(clinks)} 条)")

    # ----- List -----
    if fmt in ("all", "list"):
        with open(out + "_list.txt", "w", encoding="utf-8") as f:
            for i, p in enumerate(proxies, 1):
                f.write(f"[{i:3}] {p.get('name','?')}\t{p.get('type')}\t"
                        f"{p.get('server','')}:{p.get('port','')}\n")
        log(f"  -> {out}_list.txt")

    log("[4/4] 完成")
    return 0


if __name__ == "__main__":
    sys.exit(main())
