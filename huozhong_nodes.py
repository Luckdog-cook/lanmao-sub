#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import threading
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple

import requests
import urllib3

if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

AUTH_SERVERS = [
    "https://154.17.1.102/realms/vpn_application/protocol/openid-connect/token",
]
API_SERVERS = [
    "https://47.76.166.180/api/nodesystem/user",
]

# 从环境变量读取，避免明文写在代码里
USERNAME = os.getenv("HUOZHONG_USER", "110gfw")
PASSWORD = os.getenv("HUOZHONG_PASS", "Czy5201314.")
CLIENT_ID = "vpn-user"
CLIENT_SECRET = "i16bYq4sXxlGl3s"

ALLOWED_STATUS = {"HEALTHY"}
MAX_WORKERS = 4

OUTPUT_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)) or ".",
    "huozhong_nodes.txt",
)
CLASH_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)) or ".",
    "huozhong_clash.yaml",
)

BASE_HEADERS = {
    "User-Agent": "ktor-client",
    "X-App-Version": "1.1.21",
    "X-Device-OS": "Android",
    "Accept": "application/json",
    "Accept-Encoding": "gzip",
}

_global_session = requests.Session()
_global_session.verify = False

_lock = threading.Lock()
_login_lock = threading.Lock()
_token_state = {"token": None, "expire_at": 0.0}


def retry_request(max_retries: int = 3, backoff_factor: float = 1.5):
    def decorator(func):
        def wrapper(*args, **kwargs):
            last_exc = None
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exc = e
                    if attempt == max_retries:
                        raise
                    wait = backoff_factor ** (attempt + 1)
                    print(f"  [重试 {attempt+1}/{max_retries}] {e}，{wait:.1f}s 后重试...")
                    time.sleep(wait)
            if last_exc:
                raise last_exc
            return None
        return wrapper
    return decorator


def login_and_get_token() -> Optional[str]:
    print("[1/3] 正在登录获取最新 JWT Token...")
    payload = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "password",
        "username": USERNAME,
        "password": PASSWORD,
    }
    headers = {
        **BASE_HEADERS,
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    }

    for auth_url in AUTH_SERVERS:
        try:
            resp = _global_session.post(auth_url, data=payload, headers=headers, timeout=12)
            if resp.status_code == 200:
                data = resp.json()
                token = data.get("access_token")
                if token:
                    expires = int(data.get("expires_in", 3600))
                    with _lock:
                        _token_state["token"] = token
                        _token_state["expire_at"] = time.time() + expires - 60
                    print(f"  [OK] 登录成功！Token 有效期约 {expires // 60} 分钟")
                    return token
            else:
                print(f"  [!] {auth_url} 返回状态码 {resp.status_code}")
        except Exception as e:
            print(f"  [!] 连接 {auth_url} 异常: {e}")

    print("  [ERROR] 登录失败，请检查账号密码或后端连通性")
    return None


def ensure_token() -> str:
    with _lock:
        token = _token_state["token"]
        expire_at = _token_state["expire_at"]
    if token and time.time() < expire_at:
        return token
    
    with _login_lock:
        with _lock:
            token = _token_state["token"]
            expire_at = _token_state["expire_at"]
        if token and time.time() < expire_at:
            return token
        
        new_token = login_and_get_token()
        if not new_token:
            raise RuntimeError("Token 刷新失败")
        return new_token


@retry_request(max_retries=3)
def get_node_list(token: str) -> List[Dict]:
    print("[2/3] 正在拉取全量节点列表...")
    headers = {
        **BASE_HEADERS,
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    last_exc = None
    for api_url in API_SERVERS:
        try:
            url = f"{api_url}/nodeList?platform=android&ipv6=false"
            resp = _global_session.post(url, headers=headers, json={}, timeout=15)
            if resp.status_code == 200:
                nodes = resp.json()
                if isinstance(nodes, list):
                    print(f"  [OK] 成功获取 {len(nodes)} 个节点")
                    return nodes
                last_exc = Exception(f"{api_url} 返回结构异常")
            else:
                last_exc = Exception(f"{api_url} 状态码 {resp.status_code}")
        except Exception as e:
            last_exc = e

    if last_exc:
        raise last_exc
    return []


@retry_request(max_retries=3)
def get_client_config(node_id: int, token: str) -> Dict:
    headers = {
        **BASE_HEADERS,
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    last_exc = None
    for api_url in API_SERVERS:
        try:
            url = f"{api_url}/clientConfig"
            payload = {"nodeId": node_id, "ipv6": False}
            with requests.Session() as s:
                s.verify = False
                resp = s.post(url, headers=headers, json=payload, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data:
                    return data
                last_exc = Exception(f"节点 {node_id} 返回空配置")
            elif resp.status_code == 401:
                ensure_token()
                last_exc = Exception(f"节点 {node_id} 鉴权失败 401")
            else:
                last_exc = Exception(f"节点 {node_id} 状态码 {resp.status_code}")
        except Exception as e:
            last_exc = e

    if last_exc:
        raise last_exc
    return {}


def extract_node_name(node: Dict) -> str:
    name_parts = []
    if region := node.get("regionNameCn"):
        name_parts.append(region.strip())
    if name := node.get("nameCn"):
        name_parts.append(name.strip())
    elif name := node.get("nameEn"):
        name_parts.append(name.strip())

    if tag := node.get("tagCn"):
        name_parts.append(f"({tag.strip()})")

    result = " - ".join(name_parts) if name_parts else f"Node-{node.get('nodeId', '未知')}"
    return result


def generate_trojan_link(config: Dict, node_name: str) -> str:
    servers = config.get("settings", {}).get("servers", [])
    if not servers:
        raise ValueError("缺少 servers 配置")

    s = servers[0]
    address = s.get("address")
    port = s.get("port")
    password = s.get("password")
    if not all([address, port, password]):
        raise ValueError("Trojan 缺少核心连接信息")

    stream = config.get("streamSettings", {})
    tls = stream.get("tlsSettings", {})
    ws = stream.get("wsSettings", {})
    grpc = stream.get("grpcSettings", {})
    network = stream.get("network", "tcp")

    params = {}

    if stream.get("security") == "tls":
        params["security"] = "tls"
        if sni := tls.get("serverName"):
            params["sni"] = sni
        # 强制允许不安全连接，解决 legacy Common Name 证书报错
        params["allowInsecure"] = "1"
        if fp := tls.get("fingerprint"):
            params["fp"] = fp
        params["alpn"] = "http/1.1"

    params["type"] = network
    if network == "ws":
        if path := ws.get("path"):
            params["path"] = path
        host = (ws.get("headers") or {}).get("Host") or tls.get("serverName")
        if host:
            params["host"] = host
    elif network == "grpc" and (svc := grpc.get("serviceName")):
        params["serviceName"] = svc

    query = urllib.parse.urlencode(params)
    pwd = urllib.parse.quote(str(password), safe="")
    remark = urllib.parse.quote(node_name)
    return f"trojan://{pwd}@{address}:{port}?{query}#{remark}"


def generate_vless_link(config: Dict, node_name: str) -> str:
    vnext_list = config.get("settings", {}).get("vnext", [])
    if not vnext_list:
        raise ValueError("缺少 vnext 配置")
    vnext = vnext_list[0]
    users = vnext.get("users", [])
    if not users:
        raise ValueError("缺少 users 配置")
    user = users[0]

    stream = config.get("streamSettings", {})
    network = stream.get("network", "tcp")

    params = {
        "encryption": user.get("encryption", "none"),
        "type": network,
    }

    if flow := user.get("flow"):
        params["flow"] = flow

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
        params["allowInsecure"] = "1"
        if fp := tls.get("fingerprint"):
            params["fp"] = fp
        params["alpn"] = "http/1.1"

    if network == "ws":
        ws = stream.get("wsSettings", {})
        if path := ws.get("path"):
            params["path"] = path
        host = (ws.get("headers") or {}).get("Host") or params.get("sni")
        if host:
            params["host"] = host
    elif network == "grpc":
        grpc = stream.get("grpcSettings", {})
        if svc := grpc.get("serviceName"):
            params["serviceName"] = svc

    query = urllib.parse.urlencode(params)
    remark = urllib.parse.quote(node_name)
    return f"vless://{user['id']}@{vnext['address']}:{vnext['port']}?{query}#{remark}"


def process_node(node: Dict, token: str) -> Tuple[str, str, str]:
    node_id = node.get("nodeId")
    if not node_id:
        raise ValueError("nodeId 缺失")

    node_name = extract_node_name(node)
    config = get_client_config(node_id, token)

    if not config:
        raise ValueError("配置为空")

    protocol = (config.get("protocol") or "").lower()
    if protocol == "trojan":
        link = generate_trojan_link(config, node_name)
    elif protocol == "vless":
        link = generate_vless_link(config, node_name)
    else:
        raise ValueError(f"未知协议: {protocol}")

    return node_name, protocol.upper(), link


# ================= 新增：生成 Clash YAML =================

def _yaml_quote(s) -> str:
    if s is None:
        return '""'
    s = str(s)
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_clash_config(links: List[str]) -> str:
    proxies = []
    for link in links:
        try:
            parsed = urllib.parse.urlparse(link)
            name = urllib.parse.unquote(parsed.fragment)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            
            if link.startswith("trojan://"):
                proxy = {
                    "name": name,
                    "type": "trojan",
                    "server": parsed.hostname,
                    "port": int(parsed.port),
                    "password": urllib.parse.unquote(parsed.username or ""),
                    "udp": True,
                    "skip-cert-verify": True,
                    "sni": params.get("sni", parsed.hostname),
                }
                if params.get("alpn"):
                    proxy["alpn"] = [params.get("alpn")]
                if params.get("network") == "ws":
                    proxy["network"] = "ws"
                    proxy["ws-opts"] = {
                        "path": params.get("path", "/"),
                        "headers": {"Host": params.get("host", "")}
                    }
                proxies.append(proxy)

            elif link.startswith("vless://"):
                proxy = {
                    "name": name,
                    "type": "vless",
                    "server": parsed.hostname,
                    "port": int(parsed.port),
                    "uuid": urllib.parse.unquote(parsed.username or ""),
                    "udp": True,
                    "tls": True,
                    "skip-cert-verify": True,
                    "servername": params.get("sni", parsed.hostname),
                    "client-fingerprint": params.get("fp", "chrome"),
                    "network": params.get("type", "tcp"),
                }
                if params.get("security") == "reality":
                    proxy["reality-opts"] = {
                        "public-key": params.get("pbk", ""),
                        "short-id": params.get("sid", "")
                    }
                    if params.get("flow"):
                        proxy["flow"] = params.get("flow")
                elif params.get("flow"):
                    proxy["flow"] = params.get("flow")

                if params.get("type") == "ws":
                    proxy["ws-opts"] = {
                        "path": params.get("path", "/"),
                        "headers": {"Host": params.get("host", "")}
                    }
                elif params.get("type") == "grpc":
                    proxy["grpc-opts"] = {
                        "grpc-service-name": params.get("serviceName", "")
                    }
                proxies.append(proxy)
        except Exception:
            continue

    if not proxies:
        return ""

    # 手动拼装 Clash YAML，避免依赖 pyyaml
    lines = []
    lines.append("# 火种VPN Clash 订阅")
    lines.append(f"# 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"# 节点数量: {len(proxies)}")
    lines.append("")
    lines.append("mixed-port: 7890")
    lines.append("allow-lan: false")
    lines.append("mode: rule")
    lines.append("log-level: info")
    lines.append("")
    lines.append("proxies:")

    for p in proxies:
        lines.append(f"  - name: {_yaml_quote(p['name'])}")
        lines.append(f"    type: {p['type']}")
        lines.append(f"    server: {_yaml_quote(p['server'])}")
        lines.append(f"    port: {p['port']}")
        if p['type'] == "trojan":
            lines.append(f"    password: {_yaml_quote(p['password'])}")
            lines.append(f"    udp: {str(p['udp']).lower()}")
            lines.append(f"    skip-cert-verify: true")
            if p.get('sni'):
                lines.append(f"    sni: {_yaml_quote(p['sni'])}")
            if p.get('alpn'):
                lines.append(f"    alpn: [{_yaml_quote(p['alpn'][0])}]")
        elif p['type'] == "vless":
            lines.append(f"    uuid: {_yaml_quote(p['uuid'])}")
            lines.append(f"    udp: {str(p['udp']).lower()}")
            lines.append(f"    tls: true")
            lines.append(f"    skip-cert-verify: true")
            if p.get('servername'):
                lines.append(f"    servername: {_yaml_quote(p['servername'])}")
            if p.get('client-fingerprint'):
                lines.append(f"    client-fingerprint: {p['client-fingerprint']}")
            if p.get('network'):
                lines.append(f"    network: {p['network']}")
            if p.get('flow'):
                lines.append(f"    flow: {_yaml_quote(p['flow'])}")
            if p.get('reality-opts'):
                lines.append("    reality-opts:")
                lines.append(f"      public-key: {_yaml_quote(p['reality-opts']['public-key'])}")
                lines.append(f"      short-id: {_yaml_quote(p['reality-opts']['short-id'])}")
            if p.get('ws-opts'):
                lines.append("    ws-opts:")
                lines.append(f"      path: {_yaml_quote(p['ws-opts']['path'])}")
                lines.append("      headers:")
                lines.append(f"        Host: {_yaml_quote(p['ws-opts']['headers']['Host'])}")
            if p.get('grpc-opts'):
                lines.append("    grpc-opts:")
                lines.append(f"      grpc-service-name: {_yaml_quote(p['grpc-opts']['grpc-service-name'])}")

    lines.append("")
    lines.append("proxy-groups:")
    lines.append('  - name: "🚀 节点选择"')
    lines.append("    type: select")
    lines.append("    proxies:")
    lines.append('      - "♻️ 自动选择"')
    lines.append('      - "DIRECT"')
    for p in proxies:
        lines.append(f"      - {_yaml_quote(p['name'])}")
    lines.append('  - name: "♻️ 自动选择"')
    lines.append("    type: url-test")
    lines.append('    url: "http://www.gstatic.com/generate_204"')
    lines.append("    interval: 300")
    lines.append("    tolerance: 50")
    lines.append("    proxies:")
    for p in proxies:
        lines.append(f"      - {_yaml_quote(p['name'])}")

    lines.append("")
    lines.append("rules:")
    lines.append("  - GEOIP,LAN,DIRECT,no-resolve")
    lines.append("  - GEOIP,CN,DIRECT")
    lines.append("  - MATCH,🚀 节点选择")
    lines.append("")

    return "\n".join(lines)


def main():
    print("=" * 60)
    print("      火种VPN - 节点全量订阅提取器 (Clash + Base64)")
    print("=" * 60)
    print(f"输出文件: {OUTPUT_FILE}")
    print(f"Clash 文件: {CLASH_FILE}\n")

    token = login_and_get_token()
    if not token:
        print("[ERROR] 登录失败，跳过本次抓取，保留旧文件")
        sys.exit(1)

    try:
        nodes = get_node_list(token)
    except Exception as e:
        print(f"[ERROR] 获取节点列表失败: {e}")
        print("[INFO] 抓取失败，保留旧文件。")
        sys.exit(1)

    if not nodes:
        print("节点列表为空，保留旧文件。")
        sys.exit(1)

    valid_nodes = [n for n in nodes if n.get("status") in ALLOWED_STATUS]
    skipped = len(nodes) - len(valid_nodes)
    print(f"  [OK] 过滤后保留 {len(valid_nodes)} 个 HEALTHY 节点（跳过 {skipped} 个）")

    if not valid_nodes:
        print("没有可用节点，保留旧文件。")
        sys.exit(1)

    out_dir = os.path.dirname(os.path.abspath(OUTPUT_FILE))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    print(f"\n[3/3] 正在并发解析 {len(valid_nodes)} 个节点...")
    print(f"      并发线程数: {MAX_WORKERS}\n")

    results: List[Tuple[int, str, str, str]] = []
    failed = 0
    total = len(valid_nodes)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {
            executor.submit(process_node, node, token): node
            for node in valid_nodes
        }
        for idx, fut in enumerate(as_completed(future_map), 1):
            node = future_map[fut]
            node_name = extract_node_name(node)
            try:
                name, proto, link = fut.result()
                results.append((node.get("nodeId"), name, proto, link))
                print(f"  [{idx:3d}/{total}] [OK]   [{proto}] {name}")
            except Exception as e:
                failed += 1
                print(f"  [{idx:3d}/{total}] [FAIL] {node_name} - {e}")

    if not results:
        print("[ERROR] 所有节点解析均失败，保留旧文件。")
        sys.exit(1)

    results.sort(key=lambda x: x[0] or 0)

    seen = set()
    unique_links = []
    for _, _, _, link in results:
        if link not in seen:
            seen.add(link)
            unique_links.append(link)

    # 写入明文链接 (给 NekoBox / v2rayNG)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(f"# 火种VPN 节点订阅 - 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# 有效节点: {len(unique_links)} / {total}\n")
        for link in unique_links:
            f.write(link + "\n")

    # 写入 Clash YAML (给 Clash Meta / mihomo)
    clash_yaml = build_clash_config(unique_links)
    if clash_yaml:
        with open(CLASH_FILE, "w", encoding="utf-8") as f:
            f.write(clash_yaml)
        print(f"\n✅ 已生成 Clash 配置：{CLASH_FILE}")
    else:
        print("\n⚠️ 没有生成 Clash 配置（可能解析失败）")

    print("\n" + "=" * 60)
    print(f"处理完成！成功导出 {len(unique_links)} 条（去重后），失败 {failed} 条")
    print(f"明文订阅: {OUTPUT_FILE}")
    print(f"Clash 订阅: {CLASH_FILE}")
    print("=" * 60)


if __name__ == "__main__":
    main()
