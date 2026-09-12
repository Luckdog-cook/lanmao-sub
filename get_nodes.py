#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
火种VPN - 获取节点 + 生成订阅 + 自动推送到固定 Gist
"""

import os
import sys
import json
import time
import urllib.parse
from datetime import datetime
from typing import List, Dict, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==================== 配置 ====================
AUTH_SERVERS = [
    "https://154.17.1.102/realms/vpn_application/protocol/openid-connect/token",
    "https://kc.huozhong.us/realms/vpn_application/protocol/openid-connect/token"
]
API_SERVERS = [
    "https://154.17.0.133/api/nodesystem/user",
    "https://api.huozhong.us/api/nodesystem/user"
]

CLIENT_ID = "vpn-user"
CLIENT_SECRET = "i16bYq4sXxlGl3s"

BASE_HEADERS = {
    "User-Agent": "ktor-client",
    "X-App-Version": "1.1.21",
    "X-Device-OS": "Android",
    "Accept": "application/json",
    "Accept-Encoding": "gzip",
}

# ==================== 登录与节点 ====================
def login(username: str, password: str) -> Optional[str]:
    payload = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "password",
        "username": username,
        "password": password,
    }
    headers = {**BASE_HEADERS, "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
    for url in AUTH_SERVERS:
        try:
            resp = requests.post(url, data=payload, headers=headers, timeout=12, verify=False)
            if resp.status_code == 200:
                token = resp.json().get("access_token")
                if token:
                    print("  ✅ 登录成功")
                    return token
        except Exception as e:
            print(f"  连接失败: {e}")
    return None

def get_node_list(token: str) -> List[Dict]:
    headers = {**BASE_HEADERS, "Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    for api_url in API_SERVERS:
        try:
            url = f"{api_url}/nodeList?platform=android"
            resp = requests.post(url, headers=headers, json={}, timeout=15, verify=False)
            if resp.status_code == 200 and isinstance(resp.json(), list):
                nodes = resp.json()
                print(f"  ✅ 获取到 {len(nodes)} 个节点")
                return nodes
        except Exception:
            continue
    raise Exception("无法获取节点列表")

def get_client_config(node_id: int, token: str) -> Optional[Dict]:
    headers = {**BASE_HEADERS, "Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    for api_url in API_SERVERS:
        try:
            url = f"{api_url}/clientConfig"
            resp = requests.post(url, headers=headers, json={"nodeId": node_id, "ipv6": False}, timeout=10, verify=False)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            continue
    return None

def extract_node_name(node: Dict) -> str:
    parts = []
    if region := node.get("regionNameCn"):
        parts.append(region.strip())
    if name := node.get("nameCn") or node.get("nameEn"):
        parts.append(name.strip())
    if tag := node.get("tagCn"):
        parts.append(f"({tag.strip()})")
    return " - ".join(parts) if parts else f"Node-{node.get('nodeId', '未知')}"

# ==================== 链接生成 ====================
def generate_trojan_link(config: Dict, node_name: str) -> str:
    s = config.get("settings", {}).get("servers", [])[0]
    address, port, password = s.get("address"), s.get("port"), s.get("password")
    stream = config.get("streamSettings", {})
    tls = stream.get("tlsSettings", {})
    ws = stream.get("wsSettings", {})
    network = stream.get("network", "tcp")

    params = {"security": "tls", "type": network, "alpn": "http/1.1"}
    if sni := tls.get("serverName"):
        params["sni"] = sni
    if tls.get("allowInsecure") is not None:
        params["allowInsecure"] = "1" if tls.get("allowInsecure") else "0"
    if fp := tls.get("fingerprint"):
        params["fp"] = fp
    if network == "ws" and (path := ws.get("path")):
        params["path"] = path
        params["host"] = tls.get("serverName", "")

    query = urllib.parse.urlencode(params)
    return f"trojan://{password}@{address}:{port}?{query}#{urllib.parse.quote(node_name)}"

def generate_vless_link(config: Dict, node_name: str) -> str:
    vnext = config.get("settings", {}).get("vnext", [])[0]
    user = vnext.get("users", [])[0]
    stream = config.get("streamSettings", {})
    network = stream.get("network", "tcp")

    params = {"encryption": user.get("encryption", "none"), "type": network}
    if stream.get("security") == "reality":
        reality = stream.get("realitySettings", {})
        params.update({
            "security": "reality",
            "pbk": reality.get("publicKey", ""),
            "fp": reality.get("fingerprint", "chrome"),
            "sni": reality.get("serverName", ""),
            "sid": reality.get("shortId", ""),
        })
    elif stream.get("security") == "tls":
        tls = stream.get("tlsSettings", {})
        params["security"] = "tls"
        if sni := tls.get("serverName"):
            params["sni"] = sni
        params["alpn"] = "http/1.1"

    if network == "ws":
        ws = stream.get("wsSettings", {})
        if path := ws.get("path"):
            params["path"] = path
        params["host"] = params.get("sni", "")

    query = urllib.parse.urlencode(params)
    return f"vless://{user['id']}@{vnext['address']}:{vnext['port']}?{query}#{urllib.parse.quote(node_name)}"

# ==================== Clash 生成 ====================
def generate_clash_proxy(config: Dict, node_name: str) -> Optional[Dict]:
    protocol = config.get("protocol", "").lower()
    stream = config.get("streamSettings", {})
    network = stream.get("network", "tcp")

    if protocol == "trojan":
        s = config.get("settings", {}).get("servers", [])[0]
        proxy = {
            "name": node_name,
            "type": "trojan",
            "server": s.get("address"),
            "port": s.get("port"),
            "password": s.get("password"),
            "udp": True,
        }
        if stream.get("security") == "tls":
            tls = stream.get("tlsSettings", {})
            proxy["sni"] = tls.get("serverName", "")
            proxy["skip-cert-verify"] = bool(tls.get("allowInsecure"))
            if fp := tls.get("fingerprint"):
                proxy["client-fingerprint"] = fp
        if network == "ws":
            ws = stream.get("wsSettings", {})
            proxy["network"] = "ws"
            proxy["ws-opts"] = {"path": ws.get("path", "/")}
            if host := stream.get("tlsSettings", {}).get("serverName"):
                proxy["ws-opts"]["headers"] = {"Host": host}
        return proxy

    elif protocol == "vless":
        vnext = config.get("settings", {}).get("vnext", [])[0]
        user = vnext.get("users", [])[0]
        proxy = {
            "name": node_name,
            "type": "vless",
            "server": vnext.get("address"),
            "port": vnext.get("port"),
            "uuid": user.get("id"),
            "udp": True,
            "tls": stream.get("security") in ("tls", "reality"),
        }
        if stream.get("security") == "reality":
            reality = stream.get("realitySettings", {})
            proxy["reality-opts"] = {
                "public-key": reality.get("publicKey", ""),
                "short-id": reality.get("shortId", ""),
            }
            proxy["servername"] = reality.get("serverName", "")
            proxy["client-fingerprint"] = reality.get("fingerprint", "chrome")
        elif stream.get("security") == "tls":
            tls = stream.get("tlsSettings", {})
            proxy["servername"] = tls.get("serverName", "")
            proxy["skip-cert-verify"] = bool(tls.get("allowInsecure"))
            if fp := tls.get("fingerprint"):
                proxy["client-fingerprint"] = fp
        if network == "ws":
            ws = stream.get("wsSettings", {})
            proxy["network"] = "ws"
            proxy["ws-opts"] = {"path": ws.get("path", "/")}
        return proxy
    return None

def build_clash_yaml(proxies: List[Dict]) -> str:
    proxy_names = [p["name"] for p in proxies]
    yaml = f"""# 火种VPN Clash 配置
# 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

mixed-port: 7890
allow-lan: true
mode: rule
log-level: info
external-controller: 127.0.0.1:9090

proxies:
"""
    for p in proxies:
        yaml += f"  - {json.dumps(p, ensure_ascii=False)}\n"

    yaml += f"""
proxy-groups:
  - name: 🚀 节点选择
    type: select
    proxies:
      - ♻️ 自动选择
      - 🎯 全球直连
"""
    for name in proxy_names:
        yaml += f"      - {name}\n"

    yaml += """  - name: ♻️ 自动选择
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50
    proxies:
"""
    for name in proxy_names:
        yaml += f"      - {name}\n"

    yaml += """  - name: 🎯 全球直连
    type: select
    proxies:
      - DIRECT

rules:
  - GEOIP,CN,🎯 全球直连
  - MATCH,🚀 节点选择
"""
    return yaml

# ==================== 推送到 Gist ====================
def update_gist(content: str, gist_id: str, github_token: str, filename: str = "subscription.txt"):
    url = f"https://api.github.com/gists/{gist_id}"
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    data = {
        "files": {
            filename: {
                "content": content
            }
        }
    }
    resp = requests.patch(url, headers=headers, json=data, timeout=30)
    if resp.status_code == 200:
        print(f"  ✅ 已成功更新 Gist: {filename}")
        return True
    else:
        print(f"  ❌ 更新 Gist 失败: {resp.status_code} - {resp.text[:200]}")
        return False

# ==================== 主流程 ====================
def process_account(username: str, password: str):
    print(f"\n账号: {username}")
    token = login(username, password)
    if not token:
        return [], []

    try:
        nodes = get_node_list(token)
    except Exception as e:
        print(f"获取节点失败: {e}")
        return [], []

    links = []
    clash_proxies = []
    for idx, node in enumerate(nodes, 1):
        node_id = node.get("nodeId")
        if not node_id:
            continue
        name = extract_node_name(node)
        try:
            config = get_client_config(node_id, token)
            if not config:
                continue
            protocol = config.get("protocol", "").lower()
            if protocol == "trojan":
                link = generate_trojan_link(config, name)
            elif protocol == "vless":
                link = generate_vless_link(config, name)
            else:
                continue
            links.append(link)
            proxy = generate_clash_proxy(config, name)
            if proxy:
                clash_proxies.append(proxy)
            print(f"  [{idx:3d}/{len(nodes)}] ✅ {protocol.upper()} {name}")
        except Exception:
            print(f"  [{idx:3d}/{len(nodes)}] ❌ {name}")

    print(f"成功导出 {len(links)} 条")
    return links, clash_proxies

def main():
    accounts_raw = os.getenv("ACCOUNTS", "").strip()
    gist_id = os.getenv("GIST_ID", "").strip()
    github_token = os.getenv("GIST_TOKEN", "").strip()

    if not accounts_raw:
        print("请配置 Secrets: ACCOUNTS")
        sys.exit(1)

    all_links = []
    all_proxies = []

    for line in accounts_raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        links, proxies = process_account(parts[0], parts[1])
        all_links.extend(links)
        all_proxies.extend(proxies)

    # 生成通用订阅内容
    sub_content = f"# 火种VPN 订阅 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    sub_content += "\n".join(all_links)

    # 本地也保存一份
    with open("subscription.txt", "w", encoding="utf-8") as f:
        f.write(sub_content)

    if all_proxies:
        clash_content = build_clash_yaml(all_proxies)
        with open("clash.yaml", "w", encoding="utf-8") as f:
            f.write(clash_content)

    print(f"\n共生成 {len(all_links)} 条节点")

    # 推送到固定 Gist
    if gist_id and github_token:
        print("\n正在更新固定 Gist...")
        update_gist(sub_content, gist_id, github_token, "subscription.txt")
        if all_proxies:
            update_gist(clash_content, gist_id, github_token, "clash.yaml")
    else:
        print("未配置 GIST_ID 或 GIST_TOKEN，跳过推送")

if __name__ == "__main__":
    main()
