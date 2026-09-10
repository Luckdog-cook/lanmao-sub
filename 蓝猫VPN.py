#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
蓝猫VPN 智能订阅脚本
- 3 天内：自由刷新现有节点
- 超过 3 天：自动换全新账号 + 全新订阅
"""

import sys, os, json, base64, random, string, ssl, time
from datetime import datetime, timezone

try:
    import urllib.request as ur
    import urllib.error
except ImportError:
    sys.exit("需要 Python 3")

# ======================== 配置 ========================
BOOT_URL = "https://qiyusur.oss-cn-shanghai.aliyuncs.com/2002552026.log"
FALLBACK_GATEWAY = "http://8.210.52.158:8020"
UA = "okhttp/4.12.0"
TOKEN_MAX_AGE = 3 * 24 * 3600          # 3 天
# ======================================================

try:
    OUT_DIR = os.path.dirname(os.path.abspath(__file__))
except NameError:
    OUT_DIR = os.getcwd()

TOKEN_FILE = os.path.join(OUT_DIR, "token.json")
NODES_FILE = os.path.join(OUT_DIR, "nodes.txt")
SUB64_FILE = os.path.join(OUT_DIR, "nodes_sub_base64.txt")

DEVICE_ID = "py-" + "".join(random.choices(string.hexdigits.lower(), k=12))


def http(method, url, body=None, headers=None, timeout=25):
    h = {"User-Agent": UA, "Accept": "*/*"}
    if headers:
        h.update(headers)
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        h["Content-Type"] = "application/json"
    req = ur.Request(url, data=data, headers=h, method=method)
    try:
        with ur.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except ur.error.URLError as e:
        msg = str(getattr(e, "reason", e))
        if "CERTIFICATE" in msg.upper():
            try:
                ctx = ssl._create_unverified_context()
                with ur.urlopen(req, timeout=timeout, context=ctx) as r:
                    return r.status, r.read().decode("utf-8", "replace")
            except Exception as e2:
                return -1, "ERROR: %s" % e2
        return -1, "ERROR: %s" % e
    except Exception as e:
        return -1, "ERROR: %s" % e


def headers_for(jwt=None, md5=None, dev="1"):
    h = {"devicetype": dev, "deviceid": DEVICE_ID, "devicename": "python"}
    if jwt:
        h["token"] = jwt
    if md5:
        h["authtoken"] = md5
    return h


def get_gateway():
    st, body = http("GET", BOOT_URL)
    if st == 200:
        try:
            gw = json.loads(body).get("log")
            if gw:
                return gw.rstrip("/")
        except Exception:
            pass
    return FALLBACK_GATEWAY


def save_token(md5_tok, jwt, email="", created_at=None):
    if created_at is None:
        created_at = int(time.time())
    data = {
        "token": md5_tok or "",
        "auth": jwt or "",
        "email": email,
        "created_at": created_at,
        "created_at_str": datetime.fromtimestamp(created_at, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    }
    with open(TOKEN_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print("[*] token 已保存 (创建于 %s)" % data["created_at_str"])


def load_token_full():
    try:
        with open(TOKEN_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def load_token():
    d = load_token_full()
    return d.get("token") or "", d.get("auth") or ""


def token_age_seconds():
    d = load_token_full()
    created = d.get("created_at")
    if not created:
        return None
    return int(time.time()) - int(created)


def is_token_expired():
    age = token_age_seconds()
    if age is None:
        return True
    return age >= TOKEN_MAX_AGE


def format_remain():
    age = token_age_seconds()
    if age is None:
        return "无有效账号"
    remain = TOKEN_MAX_AGE - age
    if remain <= 0:
        return "已过期，下次运行将换新号"
    days = remain // 86400
    hours = (remain % 86400) // 3600
    mins = (remain % 3600) // 60
    return f"还剩 {days} 天 {hours} 小时 {mins} 分钟"


def rand_email():
    return "py" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10)) + "@gmail.com"


def fetch_subscribe(jwt, md5_tok):
    if not jwt and not md5_tok:
        print("[!] 无凭据, 先 register/login")
        return False
    gw = get_gateway()
    print("[*] 网关: %s" % gw)
    st, body = http("GET", gw + "/app/subscribe", headers=headers_for(jwt, md5_tok))
    print("[<-] app/subscribe: %s" % body[:120])
    try:
        j = json.loads(body)
    except Exception:
        print("[!] 响应不是 JSON")
        return False
    if j.get("code") != 1:
        print("[!] 拉取失败: %s" % j.get("message"))
        return False
    links = []
    for s in (j.get("data") or []):
        for n in (s.get("node") or []):
            links.append(n)
    if not links:
        print("[!] 订阅里没有节点")
        return False
    with open(NODES_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(links))
    with open(SUB64_FILE, "w") as f:
        f.write(base64.b64encode("\n".join(links).encode("utf-8")).decode())
    print("[OK] %d 个节点 -> %s" % (len(links), NODES_FILE))
    print("[OK] base64 订阅 -> %s" % SUB64_FILE)
    return True


def cmd_register(email, pwd, force_new=False):
    gw = get_gateway()
    print("[*] 注册 %s @ %s" % (email, gw))
    st, body = http("POST", gw + "/app/register",
                    body={"email": email, "password": pwd},
                    headers=headers_for())
    print("[<-] %s" % body[:200])
    try:
        j = json.loads(body)
    except Exception:
        return False
    if j.get("code") == 1 and j.get("data"):
        d = j["data"]
        save_token(d.get("token") or "", d.get("auth_data") or "", email)
        return fetch_subscribe(d.get("auth_data"), d.get("token"))
    else:
        print("[!] 注册失败, 若提示要验证码: 先向邮箱发 sendCode 后带 email_code 注册")
        return False


def cmd_login(email, pwd):
    gw = get_gateway()
    print("[*] 登录 %s @ %s" % (email, gw))
    st, body = http("POST", gw + "/app/login",
                    body={"email": email, "password": pwd},
                    headers=headers_for())
    print("[<-] %s" % body[:200])
    try:
        j = json.loads(body)
    except Exception:
        return False
    if j.get("code") == 1 and j.get("data"):
        d = j["data"]
        save_token(d.get("token") or "", d.get("auth_data") or "", email)
        return fetch_subscribe(d.get("auth_data"), d.get("token"))
    return False


def cmd_auto(force_new=False):
    d = load_token_full()
    md5_tok = d.get("token") or ""
    jwt = d.get("auth") or ""
    email = d.get("email") or ""

    if force_new:
        print("[*] 强制换新号 ...")
        return cmd_register(rand_email(), "Py12345678")

    if not (jwt or md5_tok):
        print("[*] 本地无 token，注册新号 ...")
        return cmd_register(rand_email(), "Py12345678")

    age = token_age_seconds()
    print("[*] 当前账号: %s" % (email or "(未知)"))
    print("[*] 已使用: %.1f 小时 | %s" % ((age or 0) / 3600, format_remain()))

    if is_token_expired():
        print("[*] 已超过 %d 天，自动换全新账号 ..." % (TOKEN_MAX_AGE // 86400))
        return cmd_register(rand_email(), "Py12345678")

    print("[*] 账号仍在有效期，刷新订阅 ...")
    if not fetch_subscribe(jwt, md5_tok):
        print("[*] 刷新失败（token 可能已失效），自动换新号 ...")
        return cmd_register(rand_email(), "Py12345678")
    return True


def cmd_status():
    d = load_token_full()
    if not d:
        print("[*] 当前没有本地账号")
        return
    print("=" * 50)
    print("邮箱     :", d.get("email") or "(无)")
    print("创建时间 :", d.get("created_at_str") or "未知")
    age = token_age_seconds()
    if age is not None:
        print("已使用   : %.1f 小时 (%.1f 天)" % (age / 3600, age / 86400))
    print("剩余时间 :", format_remain())
    print("token 文件:", TOKEN_FILE)
    print("=" * 50)


def cmd_gateway():
    gw = get_gateway()
    print("[*] 网关: %s" % gw)
    for p in ["app/setting", "app/banner/list", "app/version?device_type=1", "app/subscribe"]:
        st, body = http("GET", gw + "/" + p, headers=headers_for())
        print("  /%s -> %s" % (p, body[:150]))


def main():
    a = sys.argv[1:]
    if not a:
        cmd_auto()
    elif a[0] in ("force", "new", "renew"):
        cmd_auto(force_new=True)
    elif a[0] == "register":
        cmd_register(a[1] if len(a) > 1 else rand_email(),
                     a[2] if len(a) > 2 else "Py12345678")
    elif a[0] == "login" and len(a) >= 3:
        cmd_login(a[1], a[2])
    elif a[0] == "sub":
        jwt, md5_tok = load_token()[1], load_token()[0]
        fetch_subscribe(jwt, md5_tok)
    elif a[0] == "status":
        cmd_status()
    elif a[0] == "gateway":
        cmd_gateway()
    else:
        print("""用法:
  python 蓝猫VPN.py              # 智能模式（推荐）
  python 蓝猫VPN.py sub          # 只刷新当前订阅
  python 蓝猫VPN.py force        # 强制换全新账号
  python 蓝猫VPN.py status       # 查看账号状态
  python 蓝猫VPN.py register [邮箱] [密码]
  python 蓝猫VPN.py login 邮箱 密码
  python 蓝猫VPN.py gateway
""")


if __name__ == "__main__":
    main()
