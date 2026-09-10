#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BEN VPN 全节点拉取工具（支持 VLESS + Shadowsocks）
适配 GitHub Actions 自动更新
"""

import requests
import json
import time
import sys
import os
import urllib.parse
import base64

# ================= 配置区域 =================
TOKEN = os.getenv("BEN_TOKEN", "1fe45df7-aefd-4f4a-b880-e6c9cde96c6c")
BASE_URL = "https://bebrina.date"
LANG = "zh-CN"

HEADERS = {
    "User-Agent": "PupaLupa/BEN/android/1.20.8",
    "Product-Code": "BEN",
    "Accept": "application/json, text/plain, */*",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive"
}

REQUEST_INTERVAL = float(os.getenv("REQUEST_INTERVAL", "1.0"))
TIMEOUT = 15

def get_output_dir():
    if os.getenv("OUTPUT_DIR"):
        return os.getenv("OUTPUT_DIR")
    termux_shared = "/storage/emulated/0"
    if os.path.exists(termux_shared) and os.access(termux_shared, os.W_OK):
        return termux_shared
    return os.getcwd()

OUTPUT_DIR = get_output_dir()
# =========================================

def fetch_all_nodes():
    print(f"[INFO] 文件将保存到: {OUTPUT_DIR}")
    print("[1] 正在获取可用节点列表...")
    list_url = f"{BASE_URL}/app/v1/sync/available-locations?lang={LANG}"
    
    try:
        resp = requests.get(list_url, headers=HEADERS, timeout=TIMEOUT)
        resp.raise_for_status()
        nodes = resp.json()
    except Exception as e:
        print(f"❌ 获取节点列表失败: {e}")
        sys.exit(1)

    if not isinstance(nodes, list):
        print("❌ 节点列表格式异常")
        sys.exit(1)

    print(f"✅ 获取到 {len(nodes)} 个条目（含重复/自动选择）")

    processed_values = set()
    all_configs = {}
    total_count = 0

    for node in nodes:
        loc = node.get("value")
        if not loc or node.get("systemLocation") == True:
            continue
        if loc in processed_values:
            continue
        
        processed_values.add(loc)
        total_count += 1

        print(f"[{total_count}] 正在抓取节点: {node.get('translated', loc)} ({loc}) ...", end=" ")
        
        url = (
            f"{BASE_URL}/app/v1/user/location/change/and/get"
            f"?token={TOKEN}"
            f"&location={loc}"
            f"&lang={LANG}"
            f"&referrer=utm_source%3Dgoogle-play%26utm_medium%3Dorganic"
        )
        
        try:
            resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
            
            if resp.status_code == 200:
                config_text = resp.text
                if config_text and ("config:" in config_text or "outbounds" in config_text):
                    all_configs[loc] = {
                        "metadata": node,
                        "config_raw": config_text
                    }
                    print("✅ 成功")
                else:
                    all_configs[loc] = {"metadata": node, "error": "返回内容不含配置关键字"}
                    print("⚠️ 空配置")
            else:
                all_configs[loc] = {"metadata": node, "error": f"HTTP {resp.status_code}"}
                print(f"❌ HTTP {resp.status_code}")
        
        except requests.exceptions.Timeout:
            all_configs[loc] = {"metadata": node, "error": "请求超时"}
            print("❌ 超时")
        except Exception as e:
            all_configs[loc] = {"metadata": node, "error": str(e)}
            print(f"❌ 异常: {e}")

        time.sleep(REQUEST_INTERVAL)

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    output_file = os.path.join(OUTPUT_DIR, "all_nodes_full_configs.json")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(all_configs, f, ensure_ascii=False, indent=2)
    
    print(f"\n🎉 全部完成！共成功抓取 {len(all_configs)} 个唯一节点。")
    print(f"📁 原始配置已保存至: {output_file}")

    outbound_list = extract_outbounds(all_configs)
    if outbound_list:
        generate_shareable_links(outbound_list, OUTPUT_DIR)

def extract_outbounds(configs):
    outbound_list = []
    for loc, data in configs.items():
        if "error" in data:
            continue
        raw = data.get("config_raw", "")
        metadata = data.get("metadata", {})
        country = metadata.get("translated", loc)
        speed = metadata.get("speed", "")
        
        try:
            if "config:" in raw:
                start = raw.find("{")
                end = raw.rfind("}") + 1
                if start != -1 and end > start:
                    json_str = raw[start:end]
                    parsed = json.loads(json_str)
                    outbounds = parsed.get("outbounds", [])
                    for ob in outbounds:
                        if ob.get("type") in ["vless", "shadowsocks"]:
                            ob["_source_location"] = loc
                            ob["_country"] = country
                            ob["_speed"] = speed
                            if not ob.get("tag"):
                                ob["tag"] = loc
                            outbound_list.append(ob)
        except Exception as e:
            print(f"⚠️ 解析 {loc} 的 outbounds 失败: {e}")
    
    if outbound_list:
        out_file = os.path.join(OUTPUT_DIR, "all_outbounds_merged.json")
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(outbound_list, f, ensure_ascii=False, indent=2)
        print(f"📁 已提取 {len(outbound_list)} 个有效 outbound 至: {out_file}")
    
    return outbound_list

def build_vless_link(node, name):
    try:
        uuid = node.get('uuid')
        server = node.get('server')
        port = node.get('server_port')
        flow = node.get('flow', '')
        tls = node.get('tls', {})
        sni = tls.get('server_name', '')
        fp = tls.get('utls', {}).get('fingerprint', 'randomized')
        reality = tls.get('reality', {})
        pbk = reality.get('public_key', '')
        sid = reality.get('short_id', '')

        params = {
            'encryption': 'none',
            'flow': flow,
            'security': 'reality',
            'sni': sni,
            'fp': fp,
            'pbk': pbk,
            'sid': sid
        }
        query = '&'.join([f"{k}={v}" for k, v in params.items() if v])
        encoded_name = urllib.parse.quote(name, safe='')
        return f"vless://{uuid}@{server}:{port}?{query}#{encoded_name}"
    except Exception as e:
        print(f"⚠️ VLESS 链接生成失败（{name}）: {e}")
        return None

def build_ss_link(node, name):
    try:
        server = node.get('server')
        port = node.get('server_port')
        method = node.get('method')
        password = node.get('password')
        if not all([server, port, method, password]):
            return None
        userinfo = f"{method}:{password}"
        encoded_userinfo = base64.b64encode(userinfo.encode('utf-8')).decode('utf-8')
        encoded_name = urllib.parse.quote(name, safe='')
        return f"ss://{encoded_userinfo}@{server}:{port}#{encoded_name}"
    except Exception as e:
        print(f"⚠️ SS 链接生成失败（{name}）: {e}")
        return None

def generate_shareable_links(outbound_list, output_dir):
    supported_types = ['vless', 'shadowsocks']
    
    unique_nodes = []
    seen = set()
    for node in outbound_list:
        typ = node.get('type')
        if typ not in supported_types:
            continue
        if typ == 'vless':
            key = (node['server'], node['server_port'], node['uuid'], 
                   node.get('tls', {}).get('reality', {}).get('public_key', ''))
        elif typ == 'shadowsocks':
            key = (node['server'], node['server_port'], node.get('method'), node.get('password'))
        else:
            continue
        if key not in seen:
            seen.add(key)
            unique_nodes.append(node)
    
    if not unique_nodes:
        print("⚠️ 未提取到任何可识别的节点")
        return

    print(f"✅ 去重后共有 {len(unique_nodes)} 个有效节点（含 VLESS / Shadowsocks）")

    groups = {}
    for node in unique_nodes:
        country = node.get("_country", "未知")
        speed = node.get("_speed", "")
        typ = node.get('type')
        group_key = (country, speed, typ)
        groups.setdefault(group_key, []).append(node)

    links = []
    for (country, speed, typ), nodes in groups.items():
        proto_abbr = "VLESS" if typ == 'vless' else "SS"
        base_name = f"{country}-{speed}" if speed else country
        if len(nodes) == 1:
            name = f"{base_name} ({proto_abbr})"
            link = build_vless_link(nodes[0], name) if typ == 'vless' else build_ss_link(nodes[0], name)
            if link:
                links.append(link)
        else:
            sorted_nodes = sorted(nodes, key=lambda x: (x.get('server', ''), x.get('tag', '')))
            for idx, node in enumerate(sorted_nodes, start=1):
                name = f"{base_name} ({proto_abbr})-{idx:02d}"
                link = build_vless_link(node, name) if typ == 'vless' else build_ss_link(node, name)
                if link:
                    links.append(link)

    if not links:
        print("⚠️ 未生成任何有效链接")
        return

    out_file = os.path.join(output_dir, "all_nodes_sharable_links.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(links))
    print(f"📁 已生成 {len(links)} 条可直接导入的链接（VLESS + SS）至: {out_file}")

    try:
        content = "\n".join(links)
        encoded = base64.b64encode(content.encode('utf-8')).decode('utf-8')
        sub_file = os.path.join(output_dir, "subscription_base64.txt")
        with open(sub_file, "w", encoding="utf-8") as f:
            f.write(encoded)
        print(f"📁 已生成 Base64 订阅内容至: {sub_file}")
    except Exception as e:
        print(f"⚠️ 生成 Base64 订阅失败: {e}")

if __name__ == "__main__":
    print("🚀 BEN VPN 全节点拉取工具（支持 VLESS + Shadowsocks）")
    print(f"当前 Token: {TOKEN[:8]}...")
    fetch_all_nodes()
