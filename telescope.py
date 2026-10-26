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
    "ar": "🇦🇷", "br": "🇧🇷", "mx": "🇲🇽",
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
    "ar": "阿根廷", "br": "巴西", "mx": "墨西哥",
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
    groups = {"proxy-groups": [
        {"name": gname, "type": "select", "proxies": ["♻️ 自动选择"] + names},
        {"name": "♻️ 自动选择", "type": "url-test", "url": "http://www.gstatic.com/generate_204",
         "interval": 300, "tolerance": 80, "proxies": names},
        {"name": "🐟 漏网之鱼", "type": "select", "proxies": [gname, "♻️ 自动选择", "DIRECT"]},
        {"name": "🛑 广告拦截", "type": "select", "proxies": ["REJECT", "DIRECT"]},
        {"name": "🍎 苹果服务", "type": "select", "proxies": ["DIRECT", gname]},
        {"name": "📣 谷歌服务", "type": "select", "proxies": [gname, "♻️ 自动选择"]},
        {"name": "📲 电报消息", "type": "select", "proxies": [gname, "♻️ 自动选择"]},
        {"name": "🎬 流媒体验", "type": "select", "proxies": [gname, "♻️ 自动选择"]},
        {"name": "Ⓜ️ 微软服务", "type": "select", "proxies": ["DIRECT", gname]},
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
