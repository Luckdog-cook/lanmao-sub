#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
火种VPN 节点提取器 - GitHub Actions 专用版
支持环境变量 / Secrets / config.json
"""

import json
import os
import sys
import time
import urllib.parse
from typing import List, Dict, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

session = requests.Session()
session.verify = False

BASE_HEADERS = {
    "User-Agent": "ktor-client",
    "X-App-Version": "1.1.21",
    "X-Device-OS": "Android",
    "Accept": "application/json",
    "Accept-Encoding": "gzip",
}


def load_account():
    username = os.getenv("HUOZHONG_USERNAME", "").strip()
    password = os.getenv("HUOZHONG_PASSWORD", "").strip()

    if username and password:
        print("✅ 使用环境变量/Secrets 中的账号")
        return username, password

    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                username = str(data.get("username", "")).strip()
                password = str(data.get("password", "")).strip()
                if username and password:
                    print("✅ 使用 config.json 中的账号")
                    return username, password
        except Exception as e:
            print(f"⚠️ 读取 config.json 失败: {e}")

    print("❌ 未找到账号密码，请设置 HUOZHONG_USERNAME / HUOZHONG_PASSWORD 或填写 config.json")
    sys.exit(1)


def login_and_get_token(username: str, password: str) -> Optional[str]:
    print("[1/3] 正在登录获取最新 Token...")
    payload = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "password",
        "username": username,
        "password": password,
    }
    headers = {
        **BASE_HEADERS,
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Host": "kc.huozhong.us"
    }

    for auth_url in AUTH_SERVERS:
        try:
            resp = session.post(auth_url, data=payload, headers=headers, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                token = data.get("access_token")
                if token:
                    expires = data.get("expires_in", 0) // 60
                    print(f"  [OK] 登录成功，Token 有效约 {expires} 分钟")
                    return token
            else:
                print(f"  [!] {auth_url} 返回 {resp.status_code}")
        except Exception as e:
            print(f"  [!] 连接 {auth_url} 异常: {e}")
    return None


def get_node_list(token: str) -> List[Dict]:
    print("[2/3] 正在拉取节点列表...")
    headers = {
        **BASE_HEADERS,
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Host": "api.huozhong.us"
    }
    for api_url in API_SERVERS:
        try:
            url = f"{api_url}/nodeList?platform=android"
            resp = session.post(url, headers=headers, json={}, timeout=20)
            if resp.status_code == 200:
                nodes = resp.json()
                if isinstance(nodes, list):
                    print(f"  [OK] 获取到 {len(nodes)} 个节点")
                    return nodes
        except Exception:
            continue
    raise Exception("所有 API 均无法连接")


def get_client_config(node_id: int, token: str) -> Optional[Dict]:
    headers = {
        **BASE_HEADERS,
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Host": "api.huozhong.us"
    }
    for api_url in API_SERVERS:
        try:
            url = f"{api_url}/clientConfig"
            resp = session.post(url, headers=headers, json={"nodeId": node_id, "ipv6": False}, timeout=12)
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
    return " - ".join(parts) if parts else f"Node-{node.get('nodeId')}"


def generate_trojan_link(config: Dict, node_name: str) -> str:
    s = config.get("settings", {}).get("servers", [])[0]
    address, port, password = s.get("address"), s.get("port"), s.get("password")
    stream = config.get("streamSettings", {})
    tls = stream.get("tlsSettings", {})
    ws = stream.get("wsSettings", {})
    network = stream.get("network", "tcp")

    params = {"type": network}
    if stream.get("security") == "tls":
        params["security"] = "tls"
        if sni := tls.get("serverName"):
            params["sni"] = sni
        params["allowInsecure"] = "1" if tls.get("allowInsecure") else "0"
        if fp := tls.get("fingerprint"):
            params["fp"] = fp
        params["alpn"] = "http/1.1"
    if network == "ws":
        if path := ws.get("path"):
            params["path"] = path
        params["host"] = tls.get("serverName", "vpn-node.internal")

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
            "headerType": "none",
        })
    elif stream.get("security") == "tls":
        tls = stream.get("tlsSettings", {})
        params["security"] = "tls"
        if sni := tls.get("serverName"):
            params["sni"] = sni
        params["allowInsecure"] = "1" if tls.get("allowInsecure") else "0"
        if fp := tls.get("fingerprint"):
            params["fp"] = fp
        params["alpn"] = "http/1.1"
    if network == "ws":
        ws = stream.get("wsSettings", {})
        if path := ws.get("path"):
            params["path"] = path
        params["host"] = params.get("sni", "vpn-node.internal")

    query = urllib.parse.urlencode(params)
    return f"vless://{user['id']}@{vnext['address']}:{vnext['port']}?{query}#{urllib.parse.quote(node_name)}"


def main():
    print("=" * 60)
    print("火种VPN 节点自动更新")
    print("=" * 60)

    username, password = load_account()
    token = login_and_get_token(username, password)
    if not token:
        sys.exit(1)

    nodes = get_node_list(token)
    if not nodes:
        print("节点列表为空")
        sys.exit(1)

    output_file = "nodes.txt"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(f"# 火种VPN 自动更新订阅\n")
        f.write(f"# 更新时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# 节点数量: 正在生成...\n\n")

    success = 0
    print(f"[3/3] 正在生成 {len(nodes)} 个节点链接...")

    for idx, node in enumerate(nodes, 1):
        node_id = node.get("nodeId")
        if not node_id:
            continue
        node_name = extract_node_name(node)
        try:
            config = get_client_config(node_id, token)
            if not config:
                continue
            protocol = config.get("protocol", "").lower()
            if protocol == "trojan":
                link = generate_trojan_link(config, node_name)
            elif protocol == "vless":
                link = generate_vless_link(config, node_name)
            else:
                continue
            with open(output_file, "a", encoding="utf-8") as f:
                f.write(link + "\n")
            success += 1
            print(f"  [{idx:3d}/{len(nodes)}] OK [{protocol.upper()}] {node_name}")
        except Exception as e:
            print(f"  [{idx:3d}/{len(nodes)}] ERROR: {e}")

    with open(output_file, "r", encoding="utf-8") as f:
        content = f.read()
    content = content.replace("节点数量: 正在生成...", f"节点数量: {success}")
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(content)

    print("\n" + "=" * 60)
    print(f"完成！成功导出 {success} 条节点 → {output_file}")
    print("=" * 60)


if __name__ == "__main__":
    main()
