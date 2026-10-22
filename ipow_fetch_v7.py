#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""iPoW v7 流程抓取（适配新版 App 接口）

新版 App 的调用顺序已经变了：
  1. 注册/登录
  2. POST /p2p-lite/v2/vpn/sessions/start   （不再传 preferred_country）
  3. GET  https://sub.ipow.ai/sub/<token>?session_id=<sid>[&country=XX]
     - 不带 session_id 会 400 invalid_session_id
     - 未授权账号返回的是占位凭据：REPLACE_WITH_REALITY_PUBLIC_KEY /
       REPLACE_WITH_STRONG_HYSTERIA2_PASSWORD
  4. 旧版 /p2p-lite/v2/dht/capability 已不可用（4 个 core 节点全部 503）

本脚本只做「按新流程拉取 + 严格识别占位符」，
有真凭据才输出 ipow.txt，否则明确报错，不会写出假节点。
"""

import json
import ssl
import sys
import urllib.parse
import urllib.request

import ipow_nodes as lib

CORE_COUNTRIES = ["HK", "JP", "SG", "US"]
PLACEHOLDER_MARKERS = ("REPLACE_WITH", "REPLACE_WITH_REALITY_PUBLIC_KEY",
                       "REPLACE_WITH_STRONG_HYSTERIA2_PASSWORD")


def fetch_profile(sub_url, session_id, country=None, ua="iPoW/1.0.0"):
    q = {"session_id": session_id}
    if country:
        q["country"] = country
    url = sub_url + ("&" if "?" in sub_url else "?") + urllib.parse.urlencode(q)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": ua, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=25, context=ctx) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, "{}: {}".format(type(e).__name__, e)


def is_placeholder(value):
    s = str(value or "")
    return any(m in s for m in PLACEHOLDER_MARKERS)


def parse_outbounds(text):
    """把订阅返回的 sing-box 配置转成节点字典，占位凭据直接跳过"""
    try:
        cfg = json.loads(text)
    except Exception:
        return [], "not-json"
    nodes, skipped = [], 0
    for o in cfg.get("outbounds") or []:
        typ = o.get("type")
        tag = o.get("tag") or ""
        tls = o.get("tls") or {}
        if typ == "vless" and tag.endswith("-reality"):
            reality = tls.get("reality") or {}
            pk, sid = reality.get("public_key"), reality.get("short_id")
            if is_placeholder(pk):
                skipped += 1
                continue
            nodes.append({
                "node_id": tag[:-len("-reality")],
                "country_code": "",
                "server": o.get("server"),
                "port": o.get("server_port") or 443,
                "uuid": o.get("uuid"),
                "public_key": pk,
                "short_id": sid,
                "sni": tls.get("server_name") or "",
                "flow": o.get("flow") or "",
                "protocol": "vless",
            })
        elif typ == "hysteria2" and tag.endswith("-hy2"):
            pwd = o.get("password")
            if is_placeholder(pwd):
                skipped += 1
                continue
            nodes.append({
                "node_id": tag[:-len("-hy2")],
                "country_code": "",
                "server": o.get("server"),
                "port": o.get("server_port") or 443,
                "uuid": "",
                "public_key": "",
                "short_id": "",
                "hy2": {
                    "password": pwd,
                    "server": o.get("server"),
                    "server_port": o.get("server_port") or 443,
                    "sni": tls.get("server_name") or o.get("server") or "",
                },
                "protocol": "hysteria2",
            })
    return nodes, ("placeholder:{}".format(skipped) if skipped else "ok")


def main():
    client = lib.IpowClient(verbose=False)
    acct = lib.register_new_wallet(client, verbose=False)
    token = acct.get("jwt")
    sub_url = acct.get("subscription_url") or (
        "https://sub.ipow.ai/sub/" + (acct.get("subscription_token") or ""))
    print("账号: plan={} status={}".format(acct.get("plan_id"), acct.get("status")))

    sub = client._request("GET", "/v1/me/subscription", token=token).get("subscription") or {}
    print("订阅: plan={} expires={} used={}/{}".format(
        sub.get("plan_id"), sub.get("expires_at"), sub.get("used_bytes"), sub.get("total_bytes")))

    traffic = client._request("GET", "/v1/me/traffic", token=token)
    print("流量授权: allowed={} reason={}".format(traffic.get("allowed"), traffic.get("reason")))

    sess = client._request("POST", "/p2p-lite/v2/vpn/sessions/start", {
        "client_type": lib.CLIENT_TYPE,
        "device_id": "v7-fetch-01",
        "device_name": "v7-fetch",
        "client_version": lib.CLIENT_VERSION,
    }, token=token)
    sid = (sess.get("session") or {}).get("id")
    print("会话: {} mode={} 到期={}".format(sid, sess.get("mode"),
                                          (sess.get("session") or {}).get("expires_at")))

    all_nodes, report = [], {}
    for cc in CORE_COUNTRIES:
        status, text = fetch_profile(sub_url, sid, cc)
        if status != 200:
            report[cc] = "HTTP {} {}".format(status, text[:80])
            print("  [{}] HTTP {} {}".format(cc, status, text[:100]))
            continue
        nodes, note = parse_outbounds(text)
        for n in nodes:
            n["country_code"] = cc
        all_nodes.extend(nodes)
        report[cc] = "{} 个节点 ({})".format(len(nodes), note)
        print("  [{}] 200 {} 字节 -> {} 个真节点 ({})".format(cc, len(text), len(nodes), note))

    print("\n汇总: 真实凭据节点 {} 个".format(len(all_nodes)))
    if not all_nodes:
        print("❌ 服务端未下发真实凭据（订阅为占位符），本次不生成订阅文件")
        return 2

    links = []
    for n in all_nodes:
        links.append(lib.build_hy2_url(n) if n.get("protocol") == "hysteria2"
                     else lib.build_vless_url(n))
    out = "ipow.txt"
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(links) + "\n")
    print("✅ 已写入 {}（{} 条）".format(out, len(links)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
