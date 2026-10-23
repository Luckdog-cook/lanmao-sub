# -*- coding: utf-8 -*-
"""Novalinks 专用 Clash/mihomo 配置生成 (无国家分组, 节点带国旗)"""

import yaml
from clash_rules import RULES

TEST_URL = "http://www.gstatic.com/generate_204"

FLAGS = [("HK", "\U0001F1ED\U0001F1F0"), ("TW", "\U0001F1F9\U0001F1FC"),
         ("JP", "\U0001F1EF\U0001F1F5"), ("KR", "\U0001F1F0\U0001F1F7"),
         ("SG", "\U0001F1F8\U0001F1EC"), ("US", "\U0001F1FA\U0001F1F8"),
         ("GB", "\U0001F1EC\U0001F1E7"), ("CA", "\U0001F1E8\U0001F1E6"),
         ("DE", "\U0001F1E9\U0001F1EA"), ("FR", "\U0001F1EB\U0001F1F7"),
         ("NL", "\U0001F1F3\U0001F1F1"), ("IN", "\U0001F1EE\U0001F1F3"),
         ("BR", "\U0001F1E7\U0001F1F7"), ("RU", "\U0001F1F7\U0001F1FA"),
         ("AU", "\U0001F1E6\U0001F1FA"), ("UK", "\U0001F1EC\U0001F1E7")]


def rename_flag(proxies):
    out = []
    for p in proxies:
        f = "\U0001F310"
        for k, v in FLAGS:
            if k.lower() in p["name"].lower():
                f = v
                break
        q = dict(p)
        q["name"] = f + " " + p["name"]
        out.append(q)
    return out


GEOX = {
    "geodata-mode": True,
    "geox-url": {
        "geoip": "https://mirror.ghproxy.com/https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat",
        "geosite": "https://mirror.ghproxy.com/https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",
        "mmdb": "https://mirror.ghproxy.com/https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country.mmdb",
        "asn": "https://mirror.ghproxy.com/https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb",
    },
}


def build_config(base_yaml, proxies):
    d = yaml.safe_load(base_yaml) or {}
    names = [p["name"] for p in proxies]
    d["proxies"] = proxies
    d.update(GEOX)

    groups = [
        {"name": "🚀 节点选择", "type": "select",
         "proxies": ["♻️ 自动选择", "🔯 故障转移"] + list(names)},
        {"name": "♻️ 自动选择", "type": "url-test", "url": TEST_URL,
         "interval": 300, "tolerance": 50, "proxies": list(names)},
        {"name": "🔯 故障转移", "type": "fallback", "url": TEST_URL,
         "interval": 300, "proxies": list(names)},
    ]
    biz = [
        ("📲 Telegram", ["🚀 节点选择", "♻️ 自动选择"]),
        ("🤖 AI 服务", ["🚀 节点选择", "♻️ 自动选择"]),
        ("🎬 国际媒体", ["🚀 节点选择", "♻️ 自动选择"]),
        ("📺 巴哈姆特", ["🚀 节点选择", "♻️ 自动选择"]),
        ("🎵 音乐流媒体", ["🚀 节点选择", "♻️ 自动选择"]),
        ("🌏 谷歌服务", ["DIRECT", "🚀 节点选择"]),
        ("🍎 苹果服务", ["DIRECT", "🚀 节点选择"]),
        ("Ⓜ️ 微软服务", ["DIRECT", "🚀 节点选择"]),
        ("🎮 游戏平台", ["🚀 节点选择", "♻️ 自动选择"]),
        ("📢 社交媒体", ["🚀 节点选择", "♻️ 自动选择"]),
        ("🐟 兜底分流", ["🚀 节点选择", "♻️ 自动选择", "DIRECT"]),
        ("🎯 全球直连", ["DIRECT"]),
        ("🛑 广告拦截", ["REJECT"]),
    ]
    for name, pre in biz:
        members = list(pre) + list(names)
        seen, uniq = set(), []
        for m in members:
            if m not in seen:
                seen.add(m)
                uniq.append(m)
        groups.append({"name": name, "type": "select", "proxies": uniq})

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
