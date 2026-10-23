#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
小红鼠 VPN（redmouse168.com）节点抓取

逆向自官方 Android App v0.0.43（Flutter + Go 后端 api.redmouse168.com）：
  1. 邮箱验证码登录（POST /api/v1/client/auth/send-code + /auth/login），无需签名
  2. 登录即送试用：5GB 流量 / 1 天
  3. /auth/info 直接返回 subscribeUrl，订阅内容是 base64 编码的 vless 链接
  4. 节点为 VLESS + REALITY + XTLS-Vision（HK / SG / US 共 9 个）

用法：
  python redmouse_nodes.py            # 自动注册（临时邮箱）并抓取
  python redmouse_nodes.py --reuse    # 复用 account.json 里的账号
  python redmouse_nodes.py --check    # 额外做 TCP 存活探测

产出：redmouse_nodes.txt / redmouse_nodes.base64 / redmouse_account.json
"""
import argparse
import base64
import json
import os
import random
import re
import socket
import ssl
import string
import sys
import time
import urllib.error
import urllib.request

API = "https://api.redmouse168.com/api/v1/client"
UA = "RedMouse/0.0.43"
CTX = ssl._create_unverified_context()
OUT_TXT = "redmouse_nodes.txt"
OUT_B64 = "redmouse_nodes.base64"
ACC = "redmouse_account.json"


# ---------- HTTP ----------
def api(path, body=None, token=None, timeout=20):
    headers = {"Accept": "application/json", "User-Agent": UA}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(
        API + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers=headers,
        method="POST" if body is not None else "GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode())
        except Exception:
            return {"_error": f"HTTP {e.code}"}
    except Exception as e:
        return {"_error": f"{type(e).__name__}: {e}"}


def fetch_text(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": "v2rayN/6.0"})
    with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
        return r.read().decode("utf-8", "replace")


# ---------- 临时邮箱 ----------
def _mail():
    def jreq(url, data=None, headers=None):
        h = {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}
        if headers:
            h.update(headers)
        req = urllib.request.Request(url, data=json.dumps(data).encode() if data else None,
                                     headers=h, method="POST" if data else "GET")
        with urllib.request.urlopen(req, timeout=25, context=CTX) as r:
            return json.loads(r.read().decode())

    for attempt in range(3):
        try:
            doms = jreq("https://api.mail.tm/domains")
            doms = doms["hydra:member"] if isinstance(doms, dict) else doms
            cand = [d["domain"] for d in doms if d.get("isActive", True)] or [d["domain"] for d in doms]
            dom = cand[attempt % len(cand)]
            addr = "rm" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8)) + "@" + dom
            pw = "Rm" + "".join(random.choices(string.digits, k=8))
            jreq("https://api.mail.tm/accounts", {"address": addr, "password": pw})
            tok = jreq("https://api.mail.tm/token", {"address": addr, "password": pw})["token"]
            return jreq, addr, pw, tok
        except Exception as e:
            print(f"  邮箱创建第 {attempt+1} 次失败: {type(e).__name__}")
            time.sleep(3)
    return None, None, None, None


def wait_code(jreq, mtok, wait=90):
    deadline = time.time() + wait
    while time.time() < deadline:
        time.sleep(4)
        try:
            msgs = jreq("https://api.mail.tm/messages", headers={"Authorization": "Bearer " + mtok})
            msgs = msgs["hydra:member"] if isinstance(msgs, dict) else msgs
            for m in msgs:
                d = jreq("https://api.mail.tm/messages/" + m["id"],
                         headers={"Authorization": "Bearer " + mtok})
                txt = " ".join([d.get("subject") or "", d.get("text") or ""])
                mm = re.findall(r"\b(\d{4,8})\b", txt)
                if mm:
                    return mm[0]
        except Exception:
            continue
    return None


def register():
    jreq, addr, pw, mtok = _mail()
    if not jreq:
        return None
    print(f"  临时邮箱: {addr}")
    r = api("/auth/send-code", {"email": addr})
    if r.get("_error") or not r.get("message"):
        print(f"  发码失败: {r}")
        return None
    code = wait_code(jreq, mtok)
    if not code:
        print("  未收到验证码")
        return None
    r = api("/auth/login", {"email": addr, "code": code})
    tok = r.get("token")
    if not tok:
        print(f"  登录失败: {json.dumps(r, ensure_ascii=False)[:150]}")
        return None
    print(f"  登录成功: {addr}")
    return {"email": addr, "emailPassword": pw, "token": tok}


def load_acc():
    if not os.path.exists(ACC):
        return None
    try:
        d = json.load(open(ACC))
        if d.get("token") and d.get("subscribeUrl"):
            return d
    except Exception:
        pass
    return None


def save_acc(d):
    json.dump(d, open(ACC, "w", encoding="utf-8"), ensure_ascii=False, indent=2)


def tcp_alive(host, port, timeout=4.0):
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reuse", action="store_true", help="复用 account.json 的账号")
    ap.add_argument("--check", action="store_true", help="TCP 存活探测")
    ap.add_argument("--out-dir", default=".")
    args = ap.parse_args()

    acc = load_acc() if args.reuse else None
    info = None
    if acc:
        info = api("/auth/info", token=acc["token"])
        if info.get("_error") or not info.get("subscribeUrl"):
            print("旧账号失效，重新注册")
            acc = None

    if not acc:
        acc = register()
        if not acc:
            sys.exit(1)
        info = api("/auth/info", token=acc["token"])
        if not info.get("subscribeUrl"):
            print("获取账号信息失败:", json.dumps(info, ensure_ascii=False)[:200])
            sys.exit(1)

    sub_url = info["subscribeUrl"]
    used = info.get("transferUsed") or 0
    total = info.get("transferEnable") or 0
    exp = info.get("expiredAt") or 0
    print(f"账号: {info.get('email')}  类型: {info.get('userType')}")
    print(f"流量: {used/1048576:.0f}MB / {total/1048576:.0f}MB   "
          f"到期: {time.strftime('%Y-%m-%d %H:%M', time.localtime(exp)) if exp else '未知'}")
    print(f"订阅: {sub_url}")

    raw = fetch_text(sub_url)
    try:
        text = base64.b64decode(raw).decode("utf-8", "replace")
    except Exception:
        text = raw
    links = [l.strip() for l in text.splitlines() if "://" in l]
    if not links:
        print("订阅为空")
        sys.exit(1)

    if args.check:
        kept = []
        for l in links:
            mm = re.search(r"@([^:/?#]+):(\d+)", l)
            if not mm:
                continue
            if tcp_alive(mm.group(1), int(mm.group(2))):
                kept.append(l)
            else:
                print(f"  [{l.split('#')[-1] or '?'}] {mm.group(1)}:{mm.group(2)} 不通")
        links = kept

    if not links:
        print("没有可用节点，保留旧文件")
        sys.exit(1)

    os.makedirs(args.out_dir, exist_ok=True)
    body = "\n".join(links) + "\n"
    open(os.path.join(args.out_dir, OUT_TXT), "w", encoding="utf-8").write(body)
    open(os.path.join(args.out_dir, OUT_B64), "w", encoding="utf-8").write(
        base64.b64encode(body.encode()).decode())

    acc.update({"subscribeUrl": sub_url, "expiredAt": exp,
                "transferEnable": total, "transferUsed": used,
                "savedAt": int(time.time())})
    save_acc(acc)
    print(f"节点: {len(links)}  -> {OUT_TXT} / {OUT_B64}")


if __name__ == "__main__":
    main()
