#!/usr/bin/env python3
import sys, os, json, base64, random, string, ssl, time

try:
    import urllib.request as ur
    import urllib.error
except ImportError:
    sys.exit("需要 Python 3")

BOOT_URL = "https://qiyusur.oss-cn-shanghai.aliyuncs.com/2002552026.log"
FALLBACK_GATEWAY = "http://8.210.52.158:8020"
UA = "okhttp/4.12.0"

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


def save_token(md5_tok, jwt, email=""):
    with open(TOKEN_FILE, "w") as f:
        json.dump({"token": md5_tok or "", "auth": jwt or "", "email": email}, f, ensure_ascii=False)


def load_token():
    try:
        with open(TOKEN_FILE) as f:
            d = json.load(f)
        return d.get("token") or "", d.get("auth") or ""
    except Exception:
        return "", ""


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
        print("[!] 响应不是 JSON"); return False
    if j.get("code") != 1:
        print("[!] 拉取失败: %s" % j.get("message")); return False
    links = []
    for s in (j.get("data") or []):
        for n in (s.get("node") or []):
            links.append(n)
    if not links:
        print("[!] 订阅里没有节点"); return False
    with open(NODES_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(links))
    with open(SUB64_FILE, "w") as f:
        f.write(base64.b64encode("\n".join(links).encode("utf-8")).decode())
    print("[OK] %d 个节点 -> %s" % (len(links), NODES_FILE))
    print("[OK] base64 订阅 -> %s" % SUB64_FILE)
    return True


def cmd_register(email, pwd):
    gw = get_gateway()
    print("[*] 注册 %s @ %s" % (email, gw))
    st, body = http("POST", gw + "/app/register", body={"email": email, "password": pwd},
                    headers=headers_for())
    print("[<-] %s" % body[:200])
    try:
        j = json.loads(body)
    except Exception:
        return
    if j.get("code") == 1 and j.get("data"):
        d = j["data"]
        save_token(d.get("token") or "", d.get("auth_data") or "", email)
        fetch_subscribe(d.get("auth_data"), d.get("token"))
    else:
        print("[!] 注册失败, 若提示要验证码: 先向邮箱发 sendCode 后带 email_code 注册")


def cmd_login(email, pwd):
    gw = get_gateway()
    print("[*] 登录 %s @ %s" % (email, gw))
    st, body = http("POST", gw + "/app/login", body={"email": email, "password": pwd},
                    headers=headers_for())
    print("[<-] %s" % body[:200])
    try:
        j = json.loads(body)
    except Exception:
        return
    if j.get("code") == 1 and j.get("data"):
        d = j["data"]
        save_token(d.get("token") or "", d.get("auth_data") or "", email)
        fetch_subscribe(d.get("auth_data"), d.get("token"))


def cmd_auto():
    md5_tok, jwt = load_token()
    if jwt or md5_tok:
        print("[*] 使用本地 token.json (%s)" % time.strftime("%Y-%m-%d %H:%M"))
        if not fetch_subscribe(jwt, md5_tok):
            print("[*] token 可能过期, 自动重新注册一个新号 ...")
            cmd_register(rand_email(), "Py12345678")
    else:
        cmd_register(rand_email(), "Py12345678")


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
    elif a[0] == "register":
        cmd_register(a[1] if len(a) > 1 else rand_email(), a[2] if len(a) > 2 else "Py12345678")
    elif a[0] == "login" and len(a) >= 3:
        cmd_login(a[1], a[2])
    elif a[0] == "sub":
        jwt, md5_tok = load_token()[1], load_token()[0]
        fetch_subscribe(jwt, md5_tok)
    elif a[0] == "gateway":
        cmd_gateway()
    else:
        print("用法: lanmao_portable.py [register|login 邮箱 密码|sub|gateway], 无参数=全自动")


if __name__ == "__main__":
    main()
