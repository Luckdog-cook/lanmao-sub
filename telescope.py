#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Telescope VPN (www.telescopes.vip) 逆向抓取脚本
接口: JSON-RPC  POST {api}/json-rpc
  - GetStarHomeApiDomain  获取 API 域名池
  - V5TrialLogin          试用登录(imei 设备号) -> token(约1天)
  - GetStarHomeRouteLines loginToken -> 全部 SSR 线路
节点: SSR  auth_aes128_md5 / aes-256-cfb / tls1.2_ticket_auth
输出: telescope_clash.yaml / telescope_nodes.txt / telescope_sub.txt
"""
import base64, json, os, random, sys, time, urllib.request

BASE_BOOT = "https://www.telescopes.vip/json-rpc"
HERE = os.path.dirname(os.path.abspath(__file__))
STATE_F = os.path.join(HERE, "telescope_state.json")

COMMON = {
    "channel": "official",
    "appVersion": "3.5.5",
    "platform": "android",
    "versionCode": "355",
    "systemVersion": "14",
    "phoneModel": "Xiaomi 13",
    "language": "cn",
}

FLAGS = {
    "hk": "🇭🇰", "tw": "🇹🇼", "mo": "🇲🇴", "jp": "🇯🇵", "sg": "🇸🇬",
    "us": "🇺🇸", "kr": "🇰🇷", "vn": "🇻🇳", "th": "🇹🇭", "my": "🇲🇾",
    "ph": "🇵🇭", "id": "🇮🇩", "in": "🇮🇳", "np": "🇳🇵", "mm": "🇲🇲",
    "kh": "🇰🇭", "ca": "🇨🇦", "gb": "🇬🇧", "au": "🇦🇺", "de": "🇩🇪",
    "fr": "🇫🇷", "nl": "🇳🇱", "se": "🇸🇪", "ch": "🇨🇭", "ee": "🇪🇪",
    "ie": "🇮🇪", "is": "🇮🇸", "ru": "🇷🇺", "ua": "🇺🇦", "bg": "🇧🇬",
    "hu": "🇭🇺", "es": "🇪🇸", "pt": "🇵🇹", "it": "🇮🇹", "pl": "🇵🇱",
    "za": "🇿🇦", "qa": "🇶🇦", "sa": "🇸🇦", "ae": "🇦🇪", "eg": "🇪🇬",
    "iq": "🇮🇶", "il": "🇮🇱", "az": "🇦🇿", "kz": "🇰🇿", "tr": "🇹🇷",
    "ar": "🇦🇷", "br": "🇧🇷", "mx": "🇲🇽", "cd": "🇨🇩", "uy": "🇺🇾",
    "pk": "🇵🇰", "by": "🇧🇾", "ro": "🇷🇴", "cz": "🇨🇿", "no": "🇳🇴",
    "fi": "🇫🇮", "dk": "🇩🇰", "at": "🇦🇹", "lv": "🇱🇻", "lt": "🇱🇹",
    "md": "🇲🇩", "ge": "🇬🇪", "am": "🇦🇲", "jo": "🇯🇴", "lb": "🇱🇧",
    "om": "🇴🇲", "kw": "🇰🇼", "bd": "🇧🇩", "lk": "🇱🇰", "pe": "🇵🇪",
    "cl": "🇨🇱", "co": "🇨🇴", "ec": "🇪🇨", "ng": "🇳🇬", "ke": "🇰🇪",
    "gh": "🇬🇭", "ma": "🇲🇦", "tn": "🇹🇳", "sn": "🇸🇳", "ci": "🇨🇮",
    "cm": "🇨🇲", "zw": "🇿🇼", "ug": "🇺🇬", "tz": "🇹🇿", "et": "🇪🇹",
}
CN_NAME = {
    "hk": "香港", "tw": "台湾", "mo": "澳门", "jp": "日本", "sg": "新加坡",
    "us": "美国", "kr": "韩国", "vn": "越南", "th": "泰国", "my": "马来西亚",
    "ph": "菲律宾", "id": "印尼", "in": "印度", "np": "尼泊尔", "mm": "缅甸",
    "kh": "柬埔寨", "ca": "加拿大", "gb": "英国", "au": "澳大利亚", "de": "德国",
    "fr": "法国", "nl": "荷兰", "se": "瑞典", "ch": "瑞士", "ee": "爱沙尼亚",
    "ie": "爱尔兰", "is": "冰岛", "ru": "俄罗斯", "ua": "乌克兰", "bg": "保加利亚",
    "hu": "匈牙利", "es": "西班牙", "pt": "葡萄牙", "it": "意大利", "pl": "波兰",
    "za": "南非", "qa": "卡塔尔", "sa": "沙特", "ae": "阿联酋", "eg": "埃及",
    "iq": "伊拉克", "il": "以色列", "az": "阿塞拜疆", "kz": "哈萨克斯坦", "tr": "土耳其",
    "ar": "阿根廷", "br": "巴西", "mx": "墨西哥", "cd": "刚果（金）", "uy": "乌拉圭",
    "pk": "巴基斯坦", "by": "白俄罗斯", "ro": "罗马尼亚", "cz": "捷克", "no": "挪威",
    "fi": "芬兰", "dk": "丹麦", "at": "奥地利", "lv": "拉脱维亚", "lt": "立陶宛",
    "md": "摩尔多瓦", "ge": "格鲁吉亚", "am": "亚美尼亚", "jo": "约旦", "lb": "黎巴嫩",
    "om": "阿曼", "kw": "科威特", "bd": "孟加拉国", "lk": "斯里兰卡", "pe": "秘鲁",
    "cl": "智利", "co": "哥伦比亚", "ec": "厄瓜多尔", "ng": "尼日利亚", "ke": "肯尼亚",
    "gh": "加纳", "ma": "摩洛哥", "tn": "突尼斯", "sn": "塞内加尔", "ci": "科特迪瓦",
    "cm": "喀麦隆", "zw": "津巴布韦", "ug": "乌干达", "tz": "坦桑尼亚", "et": "埃塞俄比亚",
}
ORDER = ["hk", "tw", "mo", "jp", "sg", "us", "kr", "ca", "gb", "au", "de"]

def b64u(s):
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")

def rpc(domain, method, params, rid=1, timeout=15):
    body = json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        "https://%s/json-rpc" % domain, data=body,
        headers={"Content-Type": "application/json", "User-Agent": "okhttp/4.9"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())

def get_api_domains():
    d = rpc("www.telescopes.vip", "GetStarHomeApiDomain", {})
    return d["result"]

def pick_api(domains):
    """挑一个可用的 API 域名(去掉带端口/iptv类)"""
    cands = [d for d in domains if ":" not in d]
    cands = [d for d in cands if "music" not in d] or cands
    for d in cands[:6]:
        try:
            rpc(d, "GetStarHomeApiDomain", {}, rid=9, timeout=8)
            return d
        except Exception:
            continue
    return cands[0]

def rand_imei():
    return "".join(random.choice("0123456789abcdef") for _ in range(16))

def trial_login(api):
    p = dict(COMMON)
    p["imei"] = rand_imei()
    r = rpc(api, "V5TrialLogin", p)
    if "error" in r:
        raise RuntimeError("V5TrialLogin: %s" % r["error"])
    res = r["result"]
    return res["token"], int(res.get("expiredIn", 0)), p["imei"]

def load_state():
    try:
        return json.load(open(STATE_F))
    except Exception:
        return {}

def save_state(st):
    json.dump(st, open(STATE_F, "w"), indent=1)

def get_routes(api, token, imei):
    p = dict(COMMON)
    p.update({"loginToken": token, "imei": imei})
    r = rpc(api, "GetStarHomeRouteLines", p)
    if "error" in r:
        return None, r["error"]
    return r["result"]["list"], None

def gen_ssr_link(n):
    main = "%s:%s:%s:%s:%s:%s" % (n["ip"], n["port"], n["protocol"], n["method"],
                                  n["obfs"], b64u(n["passwd"]))
    q = "obfsparam=%s&protoparam=%s&remarks=%s" % (
        b64u(n["obfsparam"]), b64u(n["protoparam"]), b64u(flag_name(n)))
    return "ssr://" + b64u(main + "/?" + q)

def flag_name(n):
    return "%s%s" % (FLAGS.get(n["flag"], "🏳️"), n["name"])

def sort_nodes(nodes):
    def key(n):
        f = n["flag"]
        return (ORDER.index(f) if f in ORDER else len(ORDER) + (len(f) % 7), f, n["name"])
    return sorted(nodes, key=key)

def clash_proxy(n):
    return {
        "name": flag_name(n), "type": "ssr",
        "server": n["ip"], "port": int(n["port"]),
        "cipher": n["method"], "password": n["passwd"],
        "protocol": n["protocol"], "protocol-param": n["protoparam"],
        "obfs": n["obfs"], "obfs-param": n["obfsparam"],
        "udp": True,
    }

# ---------------- 实测: 延迟测活 + 真实出口校正 ----------------
CTRL = "http://127.0.0.1:9099"
LOCAL_PROXY = "http://127.0.0.1:7897"

def _api(path, data=None, method="GET", timeout=8):
    req = urllib.request.Request(CTRL + path,
        data=json.dumps(data).encode() if data is not None else None, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode() or "{}")

def verify_nodes(nodes, bin_path, workers=24):
    """mihomo 内核实测。返回 {idx: (delay_ms, real_cc, real_cn, exit_ip)}，挂了的不在表里。"""
    import subprocess as sp, socket, time as _t
    from concurrent.futures import ThreadPoolExecutor
    import requests
    cfg = {"mixed-port": 7897, "mode": "global", "log-level": "warning",
           "external-controller": "127.0.0.1:9099",
           "proxies": [clash_proxy(n) for n in nodes]}
    cfgf = os.path.join(HERE, "_test_config.yaml")
    import yaml
    yaml.safe_dump(cfg, open(cfgf, "w"), allow_unicode=True)
    proc = sp.Popen([bin_path, "-f", cfgf], stdout=sp.DEVNULL, stderr=sp.DEVNULL)
    try:
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", 9099), 1).close()
                break
            except OSError:
                _t.sleep(0.3)
        else:
            raise RuntimeError("mihomo 启动失败")

        def delay_test(n):
            try:
                u = "/proxies/%s/delay?url=%s&timeout=5000" % (
                    urllib.parse.quote(flag_name(n)), "http://www.gstatic.com/generate_204")
                d = _api(u, timeout=10).get("delay")
                return flag_name(n), d
            except Exception:
                return flag_name(n), None

        with ThreadPoolExecutor(workers) as ex:
            results = dict(ex.map(delay_test, nodes))
        alive = {k: v for k, v in results.items() if v}
        print("实测存活: %d / %d" % (len(alive), len(nodes)))

        out = {}
        px = {"http": LOCAL_PROXY, "https": LOCAL_PROXY}
        for n in nodes:  # 出口检查串行(GLOBAL 单选), 只测活的
            name = flag_name(n)
            if name not in alive:
                continue
            try:
                _api("/proxies/GLOBAL", {"name": name}, method="PUT")
                j = requests.get(
                    "http://ip-api.com/json/?fields=status,countryCode,country,query",
                    proxies=px, timeout=8).json()
                if j.get("status") == "success":
                    out[name] = (alive[name], j["countryCode"], j["country"], j["query"])
                    print("  ✓ %-22s %5dms  出口 %s %s (%s)" % (name, alive[name], j["countryCode"], j["country"], j["query"]))
            except Exception:
                continue
        return out
    finally:
        proc.kill()

def rename_by_exit(n, verify):
    """按真实出口改名: 🇺🇸美国_R_2365_标称香港"""
    name = flag_name(n)
    v = verify.get(name)
    if not v:
        return None
    _, cc, _, _ = v
    cc = cc.lower()
    orig = n["name"]
    claimed = CN_NAME.get(n["flag"], n["flag"])
    tail = orig[len(claimed):].lstrip("_") if orig.startswith(claimed) else orig
    if cc == n["flag"].lower():
        return name  # 出口与标称一致
    return "%s%s_%s_标称%s" % (FLAGS.get(cc, "🏳️"), CN_NAME.get(cc, cc.upper()), tail, claimed)


def build_clash(nodes):
    proxies, names = [], []
    for n in nodes:
        name = flag_name(n)
        names.append(name)
        proxies.append({
            "name": name, "type": "ssr",
            "server": n["ip"], "port": int(n["port"]),
            "cipher": n["method"], "password": n["passwd"],
            "protocol": n["protocol"], "protocol-param": n["protoparam"],
            "obfs": n["obfs"], "obfs-param": n["obfsparam"],
            "udp": True,
        })
    gname = "🚀 节点选择"
    head = """port: 7890
socks-port: 7891
allow-lan: false
mode: rule
log-level: info
unified-delay: true
tcp-concurrent: true
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver: [223.5.5.5, 119.29.29.29]
  fallback: [8.8.8.8, 1.1.1.1]
"""
    def grp(name, first):
        """每组: 指定前缀选项 + 节点选择/自动选择 + 全部节点"""
        opts = list(first) + [gname, "♻️ 自动选择"] + names
        seen, uniq = set(), []
        for x in opts:
            if x not in seen:
                seen.add(x)
                uniq.append(x)
        return {"name": name, "type": "select", "proxies": uniq}
    groups = {"proxy-groups": [
        {"name": gname, "type": "select", "proxies": ["♻️ 自动选择"] + names},
        {"name": "♻️ 自动选择", "type": "url-test", "url": "http://www.gstatic.com/generate_204",
         "interval": 300, "tolerance": 80, "proxies": names},
        grp("🐟 漏网之鱼", ["DIRECT"]),
        grp("🛑 广告拦截", ["REJECT", "DIRECT"]),
        grp("🍎 苹果服务", ["DIRECT"]),
        grp("📣 谷歌服务", []),
        grp("📲 电报消息", []),
        grp("🎬 流媒体验", []),
        grp("Ⓜ️ 微软服务", ["DIRECT"]),
    ]}
    rules = {"rules": [
        "DOMAIN-SUFFIX,telescopes.vip,DIRECT",
        "DOMAIN-SUFFIX,telescopes.work,DIRECT",
        "DOMAIN-SUFFIX,quickg.cc,DIRECT",
        "DOMAIN,clash.razord.top,DIRECT",
        "DOMAIN,yacd.haishan.me,DIRECT",
        # ---- 广告 ----
        "DOMAIN-KEYWORD,ads,🛑 广告拦截",
        "DOMAIN-SUFFIX,doubleclick.net,🛑 广告拦截",
        "DOMAIN-SUFFIX,googlesyndication.com,🛑 广告拦截",
        "DOMAIN-SUFFIX,googleadservices.com,🛑 广告拦截",
        "DOMAIN-KEYWORD,analytics,🛑 广告拦截",
        "DOMAIN-KEYWORD,tracking,🛑 广告拦截",
        # ---- 电报 ----
        "DOMAIN-SUFFIX,telegram.org,📲 电报消息",
        "DOMAIN-SUFFIX,t.me,📲 电报消息",
        "DOMAIN-SUFFIX,tdesktop.com,📲 电报消息",
        "DOMAIN-SUFFIX,telegra.ph,📲 电报消息",
        "IP-CIDR,91.108.4.0/22,📲 电报消息,no-resolve",
        "IP-CIDR,91.108.8.0/22,📲 电报消息,no-resolve",
        "IP-CIDR,91.108.12.0/22,📲 电报消息,no-resolve",
        "IP-CIDR,91.108.16.0/22,📲 电报消息,no-resolve",
        "IP-CIDR,91.108.20.0/22,📲 电报消息,no-resolve",
        "IP-CIDR,149.154.160.0/20,📲 电报消息,no-resolve",
        # ---- 流媒体 ----
        "DOMAIN-SUFFIX,netflix.com,🎬 流媒体验",
        "DOMAIN-SUFFIX,nflxvideo.net,🎬 流媒体验",
        "DOMAIN-SUFFIX,youtube.com,🎬 流媒体验",
        "DOMAIN-SUFFIX,googlevideo.com,🎬 流媒体验",
        "DOMAIN-SUFFIX,ytimg.com,🎬 流媒体验",
        "DOMAIN-SUFFIX,disneyplus.com,🎬 流媒体验",
        "DOMAIN-SUFFIX,hulu.com,🎬 流媒体验",
        "DOMAIN-SUFFIX,twitch.tv,🎬 流媒体验",
        # ---- 谷歌 ----
        "DOMAIN-SUFFIX,google.com,📣 谷歌服务",
        "DOMAIN-SUFFIX,googleapis.com,📣 谷歌服务",
        "DOMAIN-SUFFIX,gstatic.com,📣 谷歌服务",
        "DOMAIN-SUFFIX,gmail.com,📣 谷歌服务",
        "DOMAIN-KEYWORD,google,📣 谷歌服务",
        # ---- 苹果 ----
        "DOMAIN-SUFFIX,apple.com,🍎 苹果服务",
        "DOMAIN-SUFFIX,icloud.com,🍎 苹果服务",
        "DOMAIN-SUFFIX,mzstatic.com,🍎 苹果服务",
        # ---- 微软 ----
        "DOMAIN-SUFFIX,microsoft.com,Ⓜ️ 微软服务",
        "DOMAIN-SUFFIX,windows.com,Ⓜ️ 微软服务",
        "DOMAIN-SUFFIX,office.com,Ⓜ️ 微软服务",
        "DOMAIN-SUFFIX,github.com,Ⓜ️ 微软服务",
        "DOMAIN-SUFFIX,githubusercontent.com,Ⓜ️ 微软服务",
        # ---- 国外媒体/社交 ----
        "DOMAIN-SUFFIX,twitter.com,🚀 节点选择",
        "DOMAIN-SUFFIX,x.com,🚀 节点选择",
        "DOMAIN-SUFFIX,facebook.com,🚀 节点选择",
        "DOMAIN-SUFFIX,instagram.com,🚀 节点选择",
        "DOMAIN-SUFFIX,wikipedia.org,🚀 节点选择",
        "DOMAIN-SUFFIX,openai.com,🚀 节点选择",
        "DOMAIN-SUFFIX,chatgpt.com,🚀 节点选择",
        "DOMAIN-SUFFIX,anthropic.com,🚀 节点选择",
        "DOMAIN-SUFFIX,gemini.google.com,🚀 节点选择",
        # ---- 国内直连 ----
        "DOMAIN-SUFFIX,cn,DIRECT",
        "GEOSITE,cn,DIRECT",
        "DOMAIN-KEYWORD,baidu,DIRECT",
        "DOMAIN-KEYWORD,alibaba,DIRECT",
        "DOMAIN-KEYWORD,taobao,DIRECT",
        "DOMAIN-KEYWORD,tencent,DIRECT",
        "DOMAIN-KEYWORD,bilibili,DIRECT",
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
        "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "GEOIP,CN,DIRECT",
        "MATCH,🐟 漏网之鱼",
    ]}
    import yaml
    return yaml.safe_dump({**yaml.safe_load(head), "proxies": proxies,
                           "proxy-groups": groups["proxy-groups"], "rules": rules["rules"]},
                          allow_unicode=True, sort_keys=False, width=200)

def main():
    force = "--force" in sys.argv
    api_domains = get_api_domains()
    print("API 域名池: %d 个" % len(api_domains))
    api = pick_api(api_domains)
    print("使用 API: %s" % api)

    st = load_state()
    nodes, err = None, None
    if not force and st.get("token") and st.get("expire", 0) > time.time() + 600:
        print("复用已有 token (uid=%s, 到期 %s)" % (st.get("uid"), time.strftime("%m-%d %H:%M", time.localtime(st["expire"]))))
        try:
            nodes, err = get_routes(api, st["token"], st["imei"])
        except Exception as e:
            err = str(e)
    if nodes is None:
        if err:
            print("旧 token 失效: %s -> 重新试用登录" % err)
        token, expire, imei = trial_login(api)
        print("试用登录成功 token=%s... imei=%s 到期=%s" % (token[:12], imei,
              time.strftime("%m-%d %H:%M", time.localtime(expire)) if expire else "?"))
        st = {"token": token, "imei": imei, "expire": expire, "ts": int(time.time())}
        nodes, err = get_routes(api, token, imei)
        if nodes is None:
            raise SystemExit("拿线路失败: %s" % err)

    st["expire"] = st.get("expire") or int(time.time()) + 86400
    save_state(st)
    print("节点总数: %d" % len(nodes))

    nodes = sort_nodes(nodes)

    # ---- 实测 + 真实出口校正 ----
    mihomo = os.environ.get("MIHOMO_BIN", os.path.join(HERE, "mihomo"))
    if os.path.exists(mihomo):
        verify = verify_nodes(nodes, mihomo)
        kept, rest = [], []
        for n in nodes:
            old = flag_name(n)
            vname = rename_by_exit(n, verify)
            if not vname:
                rest.append(n)  # runner 视角不可达
                continue
            d, cc = verify[old][0], verify[old][1]
            for emo in FLAGS.values():  # 去掉旧旗帜, 保留新名
                if vname.startswith(emo):
                    vname = vname[len(emo):]
                    break
            n["flag"] = cc.lower()
            n["name"] = vname
            n["_delay"] = d
            kept.append(n)
        if os.environ.get("GITHUB_ACTIONS"):
            # 海外 runner 测不通≠国内不可用: 保留并标注, 排在实测可用之后
            for n in rest:
                n["name"] = "⚠️" + n["name"]
                n["_delay"] = 99999
            kept += rest
            print("Actions 环境: 实测可用 %d, 未达 %d (保留标注)" % (len(kept) - len(rest), len(rest)))
        else:
            print("实测可用并已按真实出口改名: %d 个 (丢弃 %d 个)" % (len(kept), len(rest)))
        kept.sort(key=lambda n: n["_delay"])
        nodes = kept
    else:
        print("未找到 mihomo 内核, 跳过实测 (设 MIHOMO_BIN 启用)")

    links = [gen_ssr_link(n) for n in nodes]
    open(os.path.join(HERE, "telescope_nodes.txt"), "w").write("\n".join(links) + "\n")
    open(os.path.join(HERE, "telescope_sub.txt"), "w").write(
        base64.b64encode("\n".join(links).encode()).decode())
    open(os.path.join(HERE, "telescope_clash.yaml"), "w").write(build_clash(nodes))
    print("输出: telescope_clash.yaml / telescope_nodes.txt / telescope_sub.txt")
    import collections
    print("地区分布:", dict(collections.Counter(n["flag"] for n in nodes).most_common(10)))

if __name__ == "__main__":
    main()
