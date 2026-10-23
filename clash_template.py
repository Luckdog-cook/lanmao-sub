# -*- coding: utf-8 -*-
"""Novalinks 专用 Clash/mihomo 配置生成: 策略组 + 详细分流规则"""

import re
import yaml

TEST_URL = "http://www.gstatic.com/generate_204"

REGIONS = [
    ("HK", r"(?i)(香港|Hong|HK)"),
    ("TW", r"(?i)(台湾|台灣|Taiwan|TW)"),
    ("JP", r"(?i)(日本|Japan|JP)"),
    ("KR", r"(?i)(韩国|韓國|Korea|KR)"),
    ("SG", r"(?i)(新加坡|Singapore|SG)"),
    ("US", r"(?i)(美国|美國|United States|US)"),
    ("GB", r"(?i)(英国|英國|Britain|GB)"),
]

REGION_LABEL = {
    "HK": "\U0001F1ED\U0001F1F0 香港",
    "TW": "\U0001F1F9\U0001F1FC 台湾",
    "JP": "\U0001F1EF\U0001F1F5 日本",
    "KR": "\U0001F1F0\U0001F1F7 韩国",
    "SG": "\U0001F1F8\U0001F1EC 新加坡",
    "US": "\U0001F1FA\U0001F1F8 美国",
    "GB": "\U0001F1EC\U0001F1E7 英国",
}


def build_config(base_yaml, proxies):
    """把服务端 yaml 的 proxies 保留, 替换成自己的策略组 + 规则"""
    d = yaml.safe_load(base_yaml) or {}
    names = [p["name"] for p in proxies]
    d["proxies"] = proxies

    # 地区命中
    hit = {}
    for code, pat in REGIONS:
        got = [n for n in names if re.search(pat, n)]
        if got:
            hit[code] = got

    groups = []
    groups.append({"name": "🚀 节点选择", "type": "select",
                   "proxies": ["♻️ 自动选择", "🔯 故障转移"] + list(names)})
    groups.append({"name": "♻️ 自动选择", "type": "url-test", "url": TEST_URL,
                   "interval": 300, "tolerance": 50, "proxies": list(names)})
    groups.append({"name": "🔯 故障转移", "type": "fallback", "url": TEST_URL,
                   "interval": 300, "proxies": list(names)})
    for code, _ in REGIONS:
        if code in hit:
            groups.append({"name": REGION_LABEL[code], "type": "url-test", "url": TEST_URL,
                           "interval": 300, "tolerance": 50, "proxies": list(hit[code])})

    def refs(*extra):
        out = list(extra)
        for code, _ in REGIONS:
            if code in hit and REGION_LABEL[code] not in out:
                out.append(REGION_LABEL[code])
        out += ["♻️ 自动选择", "🚀 节点选择", "DIRECT"]
        return out

    biz = [
        ("📲 Telegram", ["🚀 节点选择"] + [REGION_LABEL[c] for c in ("SG", "US", "HK") if c in hit]),
        ("🤖 AI 服务", [REGION_LABEL[c] for c in ("US", "JP", "SG", "GB") if c in hit]),
        ("🎬 国际媒体", [REGION_LABEL[c] for c in ("HK", "TW", "US", "JP", "SG") if c in hit]),
        ("📺 巴哈姆特", [REGION_LABEL[c] for c in ("TW", "HK") if c in hit]),
        ("🎵 音乐流媒体", [REGION_LABEL[c] for c in ("HK", "TW", "SG", "US") if c in hit]),
        ("🍎 苹果服务", ["DIRECT"]),
        ("Ⓜ️ 微软服务", ["DIRECT"]),
        ("🎮 游戏平台", []),
        ("🌏 谷歌服务", []),
        ("📢 社交媒体", []),
        ("🐟 兜底分流", []),
        ("🎯 全球直连", ["DIRECT"]),
        ("🛑 广告拦截", ["REJECT"]),
    ]
    for name, pre in biz:
        members = list(pre) + ["🚀 节点选择", "♻️ 自动选择"] + names
        # 去重保序
        seen, uniq = set(), []
        for m in members:
            if m not in seen:
                seen.add(m)
                uniq.append(m)
        groups.append({"name": name, "type": "select", "proxies": list(uniq)})

    d["proxy-groups"] = groups
    d["rules"] = RULES
    d.setdefault("mode", "rule")
    d.setdefault("mixed-port", 7890)
    d["unified-delay"] = True
    d["tcp-concurrent"] = True
    d["find-process-mode"] = "off"
    d["global-client-fingerprint"] = "chrome"

    return yaml.safe_dump(d, allow_unicode=True, sort_keys=False,
                          default_flow_style=False, width=9999)


RULES = [
    # ---- 广告 / 追踪 ----
    "GEOSITE,category-ads-all,🛑 广告拦截",
    "DOMAIN-SUFFIX,doubleclick.net,🛑 广告拦截",
    "DOMAIN-SUFFIX,googlesyndication.com,🛑 广告拦截",
    "DOMAIN-SUFFIX,googleadservices.com,🛑 广告拦截",
    "DOMAIN-SUFFIX,adservice.google.com,🛑 广告拦截",
    "DOMAIN-SUFFIX,adcolony.com,🛑 广告拦截",
    "DOMAIN-SUFFIX,applovin.com,🛑 广告拦截",
    "DOMAIN-SUFFIX,unityads.unity3d.com,🛑 广告拦截",
    "DOMAIN-SUFFIX,inmobi.com,🛑 广告拦截",
    "DOMAIN-SUFFIX,umeng.com,🛑 广告拦截",
    "DOMAIN-SUFFIX,cnzz.com,🛑 广告拦截",
    "DOMAIN-SUFFIX,mmstat.com,🛑 广告拦截",

    # ---- 局域网 / 私有地址 ----
    "DOMAIN-SUFFIX,local,🎯 全球直连",
    "DOMAIN-SUFFIX,lan,🎯 全球直连",
    "IP-CIDR,0.0.0.0/8,🎯 全球直连,no-resolve",
    "IP-CIDR,10.0.0.0/8,🎯 全球直连,no-resolve",
    "IP-CIDR,100.64.0.0/10,🎯 全球直连,no-resolve",
    "IP-CIDR,127.0.0.0/8,🎯 全球直连,no-resolve",
    "IP-CIDR,169.254.0.0/16,🎯 全球直连,no-resolve",
    "IP-CIDR,172.16.0.0/12,🎯 全球直连,no-resolve",
    "IP-CIDR,192.168.0.0/16,🎯 全球直连,no-resolve",
    "IP-CIDR,224.0.0.0/4,🎯 全球直连,no-resolve",
    "IP-CIDR6,::1/128,🎯 全球直连,no-resolve",
    "IP-CIDR6,fc00::/7,🎯 全球直连,no-resolve",
    "IP-CIDR6,fe80::/10,🎯 全球直连,no-resolve",
    "GEOSITE,private,🎯 全球直连",

    # ---- AI ----
    "GEOSITE,openai,🤖 AI 服务",
    "DOMAIN-SUFFIX,chatgpt.com,🤖 AI 服务",
    "DOMAIN-SUFFIX,chat.openai.com,🤖 AI 服务",
    "DOMAIN-SUFFIX,openai.com,🤖 AI 服务",
    "DOMAIN-SUFFIX,oaistatic.com,🤖 AI 服务",
    "DOMAIN-SUFFIX,oaiusercontent.com,🤖 AI 服务",
    "DOMAIN-SUFFIX,sora.com,🤖 AI 服务",
    "DOMAIN-SUFFIX,anthropic.com,🤖 AI 服务",
    "DOMAIN-SUFFIX,claude.ai,🤖 AI 服务",
    "GEOSITE,google-gemini,🤖 AI 服务",
    "DOMAIN-SUFFIX,gemini.google.com,🤖 AI 服务",
    "DOMAIN-SUFFIX,bard.google.com,🤖 AI 服务",
    "DOMAIN-SUFFIX,generativelanguage.googleapis.com,🤖 AI 服务",
    "DOMAIN-SUFFIX,aistudio.google.com,🤖 AI 服务",
    "DOMAIN-SUFFIX,perplexity.ai,🤖 AI 服务",
    "DOMAIN-SUFFIX,poe.com,🤖 AI 服务",
    "DOMAIN-SUFFIX,midjourney.com,🤖 AI 服务",
    "DOMAIN-SUFFIX,replicate.com,🤖 AI 服务",
    "DOMAIN-SUFFIX,huggingface.co,🤖 AI 服务",
    "DOMAIN-SUFFIX,copilot.microsoft.com,🤖 AI 服务",
    "DOMAIN-SUFFIX,x.ai,🤖 AI 服务",
    "DOMAIN-SUFFIX,grok.com,🤖 AI 服务",

    # ---- Telegram ----
    "GEOSITE,telegram,📲 Telegram",
    "DOMAIN-SUFFIX,t.me,📲 Telegram",
    "DOMAIN-SUFFIX,telegram.org,📲 Telegram",
    "DOMAIN-SUFFIX,telegram.me,📲 Telegram",
    "DOMAIN-SUFFIX,telesco.pe,📲 Telegram",
    "IP-CIDR,91.108.4.0/22,📲 Telegram,no-resolve",
    "IP-CIDR,91.108.8.0/22,📲 Telegram,no-resolve",
    "IP-CIDR,91.108.12.0/22,📲 Telegram,no-resolve",
    "IP-CIDR,91.108.16.0/22,📲 Telegram,no-resolve",
    "IP-CIDR,91.108.56.0/22,📲 Telegram,no-resolve",
    "IP-CIDR,149.154.160.0/20,📲 Telegram,no-resolve",
    "IP-CIDR,95.161.76.0/24,📲 Telegram,no-resolve",

    # ---- 流媒体 ----
    "GEOSITE,netflix,🎬 国际媒体",
    "DOMAIN-SUFFIX,netflix.com,🎬 国际媒体",
    "DOMAIN-SUFFIX,nflxvideo.net,🎬 国际媒体",
    "DOMAIN-SUFFIX,nflximg.net,🎬 国际媒体",
    "DOMAIN-SUFFIX,nflxso.net,🎬 国际媒体",
    "GEOSITE,disney,🎬 国际媒体",
    "DOMAIN-SUFFIX,disneyplus.com,🎬 国际媒体",
    "DOMAIN-SUFFIX,dssott.com,🎬 国际媒体",
    "DOMAIN-SUFFIX,bamgrid.com,🎬 国际媒体",
    "GEOSITE,hbo,🎬 国际媒体",
    "DOMAIN-SUFFIX,hbomax.com,🎬 国际媒体",
    "DOMAIN-SUFFIX,max.com,🎬 国际媒体",
    "GEOSITE,primevideo,🎬 国际媒体",
    "DOMAIN-SUFFIX,primevideo.com,🎬 国际媒体",
    "GEOSITE,youtube,🎬 国际媒体",
    "DOMAIN-SUFFIX,youtube.com,🎬 国际媒体",
    "DOMAIN-SUFFIX,youtu.be,🎬 国际媒体",
    "DOMAIN-SUFFIX,ytimg.com,🎬 国际媒体",
    "DOMAIN-SUFFIX,googlevideo.com,🎬 国际媒体",
    "DOMAIN-SUFFIX,phncdn.com,🎬 国际媒体",

    # ---- 巴哈姆特 ----
    "GEOSITE,bahamut,📺 巴哈姆特",
    "DOMAIN-SUFFIX,gamer.com.tw,📺 巴哈姆特",
    "DOMAIN-SUFFIX,bahamut.com.tw,📺 巴哈姆特",

    # ---- 音乐 ----
    "DOMAIN-SUFFIX,spotify.com,🎵 音乐流媒体",
    "DOMAIN-SUFFIX,scdn.co,🎵 音乐流媒体",
    "DOMAIN-SUFFIX,deezer.com,🎵 音乐流媒体",
    "DOMAIN-SUFFIX,soundcloud.com,🎵 音乐流媒体",
    "DOMAIN-SUFFIX,music.apple.com,🎵 音乐流媒体",

    # ---- 社交 ----
    "GEOSITE,twitter,📢 社交媒体",
    "DOMAIN-SUFFIX,x.com,📢 社交媒体",
    "DOMAIN-SUFFIX,twitter.com,📢 社交媒体",
    "DOMAIN-SUFFIX,twimg.com,📢 社交媒体",
    "GEOSITE,facebook,📢 社交媒体",
    "DOMAIN-SUFFIX,facebook.com,📢 社交媒体",
    "DOMAIN-SUFFIX,fbcdn.net,📢 社交媒体",
    "DOMAIN-SUFFIX,instagram.com,📢 社交媒体",
    "DOMAIN-SUFFIX,cdninstagram.com,📢 社交媒体",
    "DOMAIN-SUFFIX,whatsapp.com,📢 社交媒体",
    "DOMAIN-SUFFIX,whatsapp.net,📢 社交媒体",
    "DOMAIN-SUFFIX,tiktok.com,📢 社交媒体",
    "DOMAIN-SUFFIX,tiktokcdn.com,📢 社交媒体",
    "DOMAIN-SUFFIX,discord.com,📢 社交媒体",
    "DOMAIN-SUFFIX,discordapp.com,📢 社交媒体",
    "DOMAIN-SUFFIX,discord.gg,📢 社交媒体",
    "DOMAIN-SUFFIX,reddit.com,📢 社交媒体",
    "DOMAIN-SUFFIX,redd.it,📢 社交媒体",

    # ---- 谷歌 ----
    "GEOSITE,google,🌏 谷歌服务",
    "DOMAIN-SUFFIX,google.com,🌏 谷歌服务",
    "DOMAIN-SUFFIX,googleapis.com,🌏 谷歌服务",
    "DOMAIN-SUFFIX,gstatic.com,🌏 谷歌服务",
    "DOMAIN-SUFFIX,googleusercontent.com,🌏 谷歌服务",
    "DOMAIN-SUFFIX,gmail.com,🌏 谷歌服务",
    "DOMAIN-SUFFIX,gvt1.com,🌏 谷歌服务",

    # ---- 苹果 ----
    "GEOSITE,apple-cn,🍎 苹果服务",
    "DOMAIN-SUFFIX,apple.com,🍎 苹果服务",
    "DOMAIN-SUFFIX,icloud.com,🍎 苹果服务",
    "DOMAIN-SUFFIX,mzstatic.com,🍎 苹果服务",
    "DOMAIN-SUFFIX,cdn-apple.com,🍎 苹果服务",

    # ---- 微软 ----
    "GEOSITE,microsoft,Ⓜ️ 微软服务",
    "DOMAIN-SUFFIX,microsoft.com,Ⓜ️ 微软服务",
    "DOMAIN-SUFFIX,windowsupdate.com,Ⓜ️ 微软服务",
    "DOMAIN-SUFFIX,live.com,Ⓜ️ 微软服务",
    "DOMAIN-SUFFIX,office.com,Ⓜ️ 微软服务",
    "DOMAIN-SUFFIX,xboxlive.com,Ⓜ️ 微软服务",

    # ---- 游戏 ----
    "DOMAIN-SUFFIX,steampowered.com,🎮 游戏平台",
    "DOMAIN-SUFFIX,steamstatic.com,🎮 游戏平台",
    "DOMAIN-SUFFIX,steamcommunity.com,🎮 游戏平台",
    "DOMAIN-SUFFIX,epicgames.com,🎮 游戏平台",
    "DOMAIN-SUFFIX,ea.com,🎮 游戏平台",
    "DOMAIN-SUFFIX,playstation.com,🎮 游戏平台",
    "DOMAIN-SUFFIX,nintendo.com,🎮 游戏平台",
    "DOMAIN-SUFFIX,battle.net,🎮 游戏平台",
    "DOMAIN-SUFFIX,riotgames.com,🎮 游戏平台",

    # ---- 开发 / 常用 ----
    "DOMAIN-SUFFIX,github.com,🚀 节点选择",
    "DOMAIN-SUFFIX,githubusercontent.com,🚀 节点选择",
    "DOMAIN-SUFFIX,github.io,🚀 节点选择",
    "DOMAIN-SUFFIX,ghcr.io,🚀 节点选择",
    "DOMAIN-SUFFIX,docker.com,🚀 节点选择",
    "DOMAIN-SUFFIX,npmjs.org,🚀 节点选择",
    "DOMAIN-SUFFIX,pypi.org,🚀 节点选择",
    "DOMAIN-SUFFIX,vercel.app,🚀 节点选择",
    "DOMAIN-SUFFIX,cloudflare.com,🚀 节点选择",
    "DOMAIN-SUFFIX,pages.dev,🚀 节点选择",

    # ---- 国内直连 ----
    "GEOSITE,cn,🎯 全球直连",
    "GEOSITE,geolocation-!cn,🐟 兜底分流",
    "GEOIP,CN,🎯 全球直连",
    "IP-CIDR,1.0.1.0/24,🎯 全球直连,no-resolve",
    "IP-CIDR,1.0.2.0/23,🎯 全球直连,no-resolve",
    "IP-CIDR,1.0.8.0/21,🎯 全球直连,no-resolve",
    "IP-CIDR,223.5.5.5/32,🎯 全球直连,no-resolve",
    "IP-CIDR,119.29.29.29/32,🎯 全球直连,no-resolve",
    "IP-CIDR,180.76.76.76/32,🎯 全球直连,no-resolve",

    # ---- 兜底 ----
    "MATCH,🐟 兜底分流",
]
