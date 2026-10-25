#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
光影VPN (com.guangying.go 3.2.1) 全节点抓取
--------------------------------------------
老版 43.159.7.5 的 SS 已停服(全端口只剩 22), 新版走 API:

  BASE  https://www.gynew.men/api/
  HDR   agentX: super-ok-http
  加密  AES-256-CBC  key=Gz#8kP@mQ2xL!nRv4Yw&TbE6sJdF0cAh  iv=Xk3N7pQ1mZ9wL5rT

流程:
  1. getInfo(imei="di:"+16hex)   设备自动注册, 返回 user id
  2. getlist(user=<id>)          返回全部线路分组 + server id + 地区
  3. getserver(user=<id>,id=<sid>) 逐个取配置 -> link 是 sing-box JSON 明文
  4. 转 vless:// URI -> base64 订阅

注意:
  - imei 必须是 "di:" + 16 位 hex
  - 必须先拿到 user id 再调 getlist, 传 user=0 会返回 ThinkPHP 错误页
  - VIP 组用参数 id, SVIP 组用 server_id, 脚本两种都试
"""
import base64, json, os, sys, time, uuid
import requests
from urllib.parse import quote

BASE = "https://www.gynew.men/api/"
KEY = b"Gz#8kP@mQ2xL!nRv4Yw&TbE6sJdF0cAh"
IV = b"Xk3N7pQ1mZ9wL5rT"
H = {"agentX": "super-ok-http", "User-Agent": "okhttp/4.9.0"}
OUT = os.environ.get("GY_OUT", "guangying.txt")
STATE = os.environ.get("GY_STATE", "guangying_state.json")
TRIES = int(os.environ.get("GY_TRIES", "6"))


def dec(s):
    try:
        from Crypto.Cipher import AES as _A
        raw = base64.b64decode(s.strip().replace("\\/", "/"))
        pt = _A.new(KEY, _A.MODE_CBC, IV).decrypt(raw)
        return pt[:-pt[-1]].decode("utf-8", "replace")
    except Exception:
        return None


def call(ep, data):
    try:
        r = requests.post(BASE + ep, data=data, headers=H, timeout=15)
        return dec(r.text) or r.text
    except Exception as e:
        return f"ERR {e}"


CC_NAME = {
    "US": "美国", "HK": "香港", "TW": "台湾", "JP": "日本", "KR": "韩国",
    "SG": "新加坡", "GB": "英国", "UK": "英国", "DE": "德国", "FR": "法国",
    "NL": "荷兰", "CA": "加拿大", "AU": "澳大利亚", "IN": "印度", "RU": "俄罗斯",
    "BR": "巴西", "VN": "越南", "TH": "泰国", "MY": "马来西亚", "PH": "菲律宾",
    "ID": "印尼", "TR": "土耳其", "AE": "阿联酋", "IT": "意大利", "ES": "西班牙",
    "SE": "瑞典", "CH": "瑞士", "PL": "波兰", "UA": "乌克兰", "ZA": "南非",
    "AR": "阿根廷", "MX": "墨西哥", "CL": "智利", "EG": "埃及", "NG": "尼日利亚",
    "KZ": "哈萨克斯坦", "PK": "巴基斯坦", "BD": "孟加拉", "LK": "斯里兰卡",
    "MM": "缅甸", "KH": "柬埔寨", "LA": "老挝", "MN": "蒙古", "NP": "尼泊尔",
}


def flag_of(cc):
    """US -> \U0001F1FA\U0001F1F8 (区域指示符)"""
    if not cc or len(cc) != 2 or not cc.isalpha():
        return "\U0001F310"
    return "".join(chr(0x1F1E6 + ord(c.upper()) - 65) for c in cc)


def geo_lookup(hosts):
    """批量查真实出口归属: {host: (cc, 中文名)}"""
    res = {}
    hs = [h for h in dict.fromkeys(hosts) if h]
    for i in range(0, len(hs), 90):
        chunk = hs[i:i + 90]
        try:
            r = requests.post(
                "http://ip-api.com/batch?fields=status,countryCode,country,query",
                json=[{"query": h} for h in chunk], timeout=20)
            for item in r.json() or []:
                if item.get("status") == "success":
                    cc = (item.get("countryCode") or "").upper()
                    name = CC_NAME.get(cc) or item.get("country") or cc
                    res[item["query"]] = (cc, name)
        except Exception as e:
            print(f"[!] 归属地查询失败: {e}")
    return res


def verify_exit(nodes, workers=5):
    """用 xray 逐个跑通并取真实出口: {id(node): (cc, 中文名, 出口IP)}"""
    import subprocess as sp
    import tempfile
    from concurrent.futures import ThreadPoolExecutor
    bin_path = os.environ.get("XRAY_BIN", "")
    if not bin_path or not os.path.exists(bin_path):
        return {}
    out = {}

    def one(args):
        i, n = args
        port = 12000 + i
        tls = n.get("tls") or {}
        ro = tls.get("reality") or {}
        net = n.get("network", "tcp")
        ss = {"network": net}
        if ro.get("enabled"):
            ss["security"] = "reality"
            ss["realitySettings"] = {"serverName": tls.get("server_name", ""),
                                     "publicKey": ro.get("public_key", ""),
                                     "shortId": ro.get("short_id", ""),
                                     "fingerprint": (tls.get("utls") or {}).get("fingerprint", "chrome")}
        else:
            ss["security"] = "tls"
            ss["tlsSettings"] = {"serverName": tls.get("server_name", ""),
                                 "fingerprint": (tls.get("utls") or {}).get("fingerprint", "chrome"),
                                 "allowInsecure": True}
        if net == "ws":
            ss["wsSettings"] = {"path": (n.get("ws_settings") or {}).get("path", "/")}
        usr = {"id": n["uuid"], "encryption": "none"}
        if n.get("flow"):
            usr["flow"] = n["flow"]
        conf = {"log": {"loglevel": "error"},
                "inbounds": [{"port": port, "listen": "127.0.0.1", "protocol": "socks",
                              "settings": {"udp": False}}],
                "outbounds": [{"protocol": "vless",
                               "settings": {"vnext": [{"address": n["server"],
                                                       "port": int(n["server_port"]),
                                                       "users": [usr]}]},
                               "streamSettings": ss}]}
        fd, path = tempfile.mkstemp(suffix=".json")
        os.write(fd, json.dumps(conf).encode()); os.close(fd)
        p = None
        try:
            p = sp.Popen([bin_path, "run", "-c", path],
                         stdout=sp.DEVNULL, stderr=sp.DEVNULL)
            time.sleep(1.5)
            r = sp.run(["curl", "-s", "-m", "7", "--socks5-hostname", f"127.0.0.1:{port}",
                        "http://ip-api.com/json/?fields=status,countryCode,country,query"],
                       capture_output=True, text=True, timeout=10)
            d = json.loads(r.stdout)
            if d.get("status") == "success":
                cc = (d.get("countryCode") or "").upper()
                return (cc, CC_NAME.get(cc) or d.get("country") or cc, d.get("query"))
        except Exception:
            pass
        finally:
            if p:
                try:
                    p.terminate(); p.wait(2)
                except Exception:
                    p.kill()
            try:
                os.unlink(path)
            except Exception:
                pass
        return None

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for n, res in zip(nodes, ex.map(one, list(enumerate(nodes)))):
            if res:
                out[id(n)] = res
    return out


def level_of(loc):
    """从销售名里取 VIP / SVIP"""
    up = (loc or "").upper()
    if "SVIP" in up:
        return "SVIP"
    if "VIP" in up:
        return "VIP"
    return ""


def to_uri(n):
    tls = n.get("tls") or {}
    r = tls.get("reality") or {}
    q = {
        "encryption": "none",
        "security": "reality" if r.get("enabled") else "tls",
        "sni": tls.get("server_name", ""),
        "fp": (tls.get("utls") or {}).get("fingerprint", "chrome"),
        "type": n.get("network", "tcp"),
    }
    if n.get("flow"):
        q["flow"] = n["flow"]
    if r.get("enabled"):
        q["pbk"] = r.get("public_key", "")
        q["sid"] = r.get("short_id", "")
    if n.get("network") == "ws":
        q["path"] = (n.get("ws_settings") or {}).get("path", "/")
    qs = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in q.items() if v)
    return f'vless://{n["uuid"]}@{n["server"]}:{n["server_port"]}?{qs}'


def register():
    """设备自动注册, 返回 (params, uid, info_raw)"""
    for i in range(TRIES):
        dev = "di:" + uuid.uuid4().hex[:16]
        p = {"imei": dev, "user": "0", "v": "3.2.1", "cid": "1",
             "a": "13", "b": "google", "c": "Pixel 7", "d": "redfin"}
        info = call("user/getInfo", p)
        if "登录成功" in (info or ""):
            try:
                uid = json.loads(info)["user"]
            except Exception:
                uid = "0"
            return {**p, "user": uid}, uid, info
        print(f"[{i+1}] {dev} 注册失败: {(info or '')[:60]}")
    return None, None, None


def load_state():
    try:
        return json.load(open(STATE))
    except Exception:
        return {}


def save_state(d):
    d["updated"] = int(time.time())
    with open(STATE, "w") as f:
        json.dump(d, f, ensure_ascii=False, indent=1)


def main():
    import time
    st = load_state()
    exp = int(st.get("expires_at", 0))
    if os.environ.get("GY_FORCE") == "1":
        exp = 0
        print("[!] GY_FORCE=1 强制重抓")
    left = exp - time.time()
    if left > 3600:
        print(f"[=] 账号未过期, 剩余 {left / 3600:.1f}h, 跳过抓取 (到期后自动重跑)")
        return 0

    p, uid, info_raw = register()
    if not p:
        print("[x] 注册失败(该 IP 额度用尽), 保留旧文件")
        return 1
    print(f"[+] 注册成功 user={uid}")
    free_days = 2
    try:
        free_days = int(json.loads(info_raw)["free_days"])
    except Exception:
        pass
    save_state({"user": uid, "expires_at": int(time.time() + free_days * 86400),
                "free_days": free_days})
    print(f"    账号有效期 {free_days} 天, 到期时间 "
          f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(time.time() + free_days * 86400))}")

    gl = call("user/getlist", p)
    try:
        groups = json.loads(gl)["group"]
    except Exception:
        print("[x] getlist 失败:", (gl or "")[:120])
        return 1

    nodes = []
    for g in groups:
        gname = g.get("name", "")
        for s in g.get("server", []):
            sid = s.get("id")
            loc = (s.get("location") or "").strip()
            link = None
            for key in ("id", "server_id", "serverId"):
                r = call("user/getserver", {**p, key: str(sid)})
                try:
                    j = json.loads(r)
                except Exception:
                    continue
                if j.get("link"):
                    link = j["link"]
                    break
            if not link:
                print(f"    {gname} / {loc} (id={sid}) 失败")
                continue
            try:
                n = json.loads(link) if link.strip().startswith("{") else json.loads(dec(link) or "{}")
            except Exception:
                print(f"    {gname} / {loc} link 解析失败")
                continue
            n["_loc"] = loc or gname
            n["_lvl"] = level_of(loc) or level_of(gname)
            nodes.append(n)
            print(f"    {gname} / {loc:<12} {n.get('server')}:{n.get('server_port')}")

    if not nodes:
        print("[x] 没有节点")
        return 1

    # 服务端的 location 是销售名, 与真实出口经常不符 -> 实测出口 IP 决定国家
    print("\n=== 归属校正 ===")
    exits = verify_exit(nodes)
    geo = geo_lookup([n.get("server") for n in nodes])
    print(f"  实测 {len(exits)}/{len(nodes)} 个节点出口")
    for n in nodes:
        if id(n) in exits:
            cc, name, ip = exits[id(n)]
            src = "实测"
        else:
            cc, name = geo.get(n.get("server"), ("", ""))
            ip, src = "", "IP归属"
            name = name or "未知"
        n["_cc"], n["_name"], n["_exit"], n["_src"] = cc, name, ip, src
        bad = "" if (name and name in n["_loc"]) else "   <-- 服务端标注不符"
        print(f"  {n['_loc']:<14} -> {name:<8} {ip or '-':<16} ({src}){bad}")

    used = {}
    for n in nodes:
        base = f"{flag_of(n['_cc'])} {n['_lvl']} {n['_name']}".replace("  ", " ").strip()
        used[base] = used.get(base, 0) + 1
        n["_tag"] = base if used[base] == 1 else f"{base}-{used[base]}"

    uris = [to_uri(n) + "#" + quote(n["_tag"]) for n in nodes]
    open(OUT, "wb").write(base64.b64encode("\n".join(uris).encode()))
    print(f"\n[+] {OUT}: {len(nodes)} 个节点")
    for n in nodes:
        print(f"    {n['_tag']:<20} {n.get('server')}:{n.get('server_port')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
