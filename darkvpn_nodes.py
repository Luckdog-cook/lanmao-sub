#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DarkVPN 节点提取器
==================

依赖:
    pip install curl_cffi cryptography

用法:
    python darkvpn_nodes.py                 # 输出到当前目录
    python darkvpn_nodes.py -o D:\\nodes      # 指定输出目录
    python darkvpn_nodes.py --domains       # 只看活动域名
    python darkvpn_nodes.py --stdout        # 节点链接打到 stdout
    python darkvpn_nodes.py -q              # 精简输出

产出:
    dark_nodes.txt     固定订阅文件（VLESS + Hysteria2）
    vless.txt / hysteria2.txt / wireguard.txt
    clash.yaml / singbox.json / sub_base64.txt
    nodes_all.json
"""
import argparse
import base64
import json
import os
import re
import secrets
import sys
import time
import urllib.parse

try:
    from curl_cffi import requests
except ImportError:
    sys.exit("缺少依赖: pip install curl_cffi cryptography")
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.exit("缺少依赖: pip install curl_cffi cryptography")

# ----------------------------------------------------------------------------
# 常量（从 libapp.so 提取）
# ----------------------------------------------------------------------------
DOMAINS = [
    "https://fasttool.org",
    "https://darkvpn.cc",
    "https://darkvpn.online",
    "https://allapp.one",
]
# secrets_encrypted 的 AES-256-GCM 密钥（硬编码在 libapp.so）
AES_KEY = bytes.fromhex("a3f1c9d8e7b24a5690cf1d3e8b47f2a1c5d6e8f09a2b4c6d8e0f1a3b5c7d9e1f")

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
IMPERSONATE = "chrome124"

# 地区排序
REGION_ORDER = ["香港", "台湾", "日本", "韩国", "新加坡", "美国", "加拿大",
                "英国", "德国", "法国", "荷兰", "土耳其", "印度", "澳大利亚"]


def region_key(label):
    for i, r in enumerate(REGION_ORDER):
        if label.startswith(r):
            return (0, i, label)
    return (1, 0, label)


def make_headers(token=None, device_id=None):
    """X-Device-Id 必需，格式 vd- + 48位hex，服务端不校验内容。"""
    h = {
        "User-Agent": UA,
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Device-Id": device_id or ("vd-" + secrets.token_hex(24)),
        "X-Client-OS": "android",
    }
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def decrypt_secrets(blob):
    """解密 secrets_encrypted: base64(iv) . base64(ciphertext+tag) . base64(tag)"""
    iv_b64, ct_b64, tag_b64 = blob.split(".")
    iv = base64.b64decode(iv_b64)
    ct = base64.b64decode(ct_b64)
    tag = base64.b64decode(tag_b64)
    return json.loads(AESGCM(AES_KEY).decrypt(iv, ct + tag, None).decode())


# ----------------------------------------------------------------------------
# 抓取
# ----------------------------------------------------------------------------
def get_domains(retries=2):
    for _ in range(retries + 1):
        for base in DOMAINS:
            try:
                r = requests.get(f"{base}/api/v1/config/domains/active",
                                 headers=make_headers(), impersonate=IMPERSONATE, timeout=15)
                if r.status_code == 200:
                    doms = (r.json().get("data") or {}).get("domains", [])
                    if doms:
                        return doms
            except Exception:
                continue
        time.sleep(1)
    return []


def fetch_config(token=None, device_id=None, retries=2):
    """请求 client-config。**无需 token**，secrets.nodes 直接明文返回。"""
    last = ""
    for attempt in range(retries + 1):
        for base in DOMAINS:
            try:
                r = requests.get(f"{base}/api/v1/nodes/client-config",
                                 headers=make_headers(token, device_id),
                                 impersonate=IMPERSONATE, timeout=20)
                if r.status_code == 200:
                    d = r.json().get("data") or r.json()
                    if d.get("secrets") or d.get("secrets_encrypted"):
                        return d, base, None
                last = f"HTTP {r.status_code}: {r.text[:120]}"
            except Exception as e:
                last = str(e)[:120]
    return None, None, last or "所有域名均失败"


def extract_nodes(data):
    """优先明文 secrets.nodes，回退解密 secrets_encrypted。"""
    secrets = data.get("secrets") or {}
    nodes = secrets.get("nodes") or {}
    auto = secrets.get("auto_nodes") or []
    if not nodes and data.get("secrets_encrypted"):
        try:
            plain = decrypt_secrets(data["secrets_encrypted"])
            nodes = plain.get("nodes") or {}
            auto = plain.get("auto_nodes") or auto
        except Exception as e:
            print(f"  ! 解密失败: {e}")
    return nodes, auto


def build_labels(data):
    labels = {}
    for g in (data.get("catalog") or {}).get("groups", []):
        for n in g.get("nodes", []):
            labels[n.get("id")] = n.get("label") or n.get("id")
    return labels


# ----------------------------------------------------------------------------
# 生成订阅
# ----------------------------------------------------------------------------
def q(s):
    return urllib.parse.quote(str(s), safe="")


def strip_pem(pem):
    return re.sub(r"-----[A-Z ]+-----|\s", "", pem or "")


def build_subscriptions(nodes, labels):
    """返回 (vless, hy2, wg, clash, singbox_outbounds, records)"""
    vless, hy2, wg = [], [], []
    clash, sb, recs = [], [], []

    order = sorted(nodes.keys(), key=lambda k: region_key(labels.get(k, k)))

    for nid in order:
        nd = nodes[nid]
        label = labels.get(nid, nid)

        # ---------- VLESS Reality ----------
        v = nd.get("vless")
        if v:
            name = f"{label}-Reality"
            p = {
                "security": "reality",
                "sni": v.get("server_name", ""),
                "fp": v.get("utls_fingerprint") or "chrome",
                "pbk": v.get("reality_public_key", ""),
                "sid": v.get("reality_short_id", ""),
                "flow": v.get("flow") or "xtls-rprx-vision",
                "type": "tcp",
            }
            vless.append(f"vless://{v['uuid']}@{v['server']}:{v['server_port']}?"
                         + urllib.parse.urlencode({k: x for k, x in p.items() if x})
                         + f"#{q(name)}")
            clash.append({
                "name": name, "type": "vless", "server": v["server"], "port": v["server_port"],
                "uuid": v["uuid"], "flow": p["flow"], "tls": True,
                "servername": p["sni"], "client-fingerprint": p["fp"],
                "reality-opts": {"public-key": p["pbk"], "short-id": p["sid"]},
                "network": "tcp", "udp": True,
            })
            sb.append({
                "type": "vless", "tag": name, "server": v["server"],
                "server_port": v["server_port"], "uuid": v["uuid"], "flow": p["flow"],
                "tls": {
                    "enabled": True, "server_name": p["sni"],
                    "utls": {"enabled": True, "fingerprint": p["fp"]},
                    "reality": {"enabled": True, "public_key": p["pbk"], "short_id": p["sid"]},
                },
            })
            recs.append({"name": name, "proto": "vless-reality", "tag": nid, **v})

        # ---------- VLESS WS (ECH over Cloudflare) ----------
        vw = nd.get("vless_ws")
        if vw:
            name = f"{label}-WS-ECH"
            ech = strip_pem(vw.get("ech_config_pem"))
            sni = vw.get("tls_server_name", "")
            path = vw.get("transport_path", "/")
            p = {"security": "tls", "sni": sni, "fp": "chrome",
                 "type": "ws", "path": path, "host": sni}
            if ech:
                p["ech"] = ech
            vless.append(f"vless://{vw['uuid']}@{vw['server']}:{vw['server_port']}?"
                         + urllib.parse.urlencode(p) + f"#{q(name)}")
            clash.append({
                "name": name, "type": "vless", "server": vw["server"], "port": vw["server_port"],
                "uuid": vw["uuid"], "tls": True, "servername": sni,
                "client-fingerprint": "chrome", "network": "ws",
                "ws-opts": {"path": path, "headers": {"Host": sni}}, "udp": True,
            })
            tls_sb = {
                "enabled": True, "server_name": sni,
                "utls": {"enabled": True, "fingerprint": "chrome"},
            }
            if ech:
                tls_sb["ech"] = {"enabled": True, "config": ech}
            sb.append({
                "type": "vless", "tag": name, "server": vw["server"],
                "server_port": vw["server_port"], "uuid": vw["uuid"],
                "tls": tls_sb,
                "transport": {"type": "ws", "path": path, "headers": {"Host": sni}},
            })
            recs.append({"name": name, "proto": "vless-ws-ech", "tag": nid, **vw})

        # ---------- Hysteria2 ----------
        h = nd.get("hysteria2")
        if h:
            name = f"{label}-Hy2"
            ports = h.get("server_ports") or ""
            port = str(ports).split("-")[0] if ports else h.get("server_port", 443)
            sni = h.get("server_name") or "bing.com"
            obfs_pw = h.get("obfs_password")
            p = {"sni": sni, "insecure": "1" if h.get("tls_insecure") else "0"}
            if ports:
                p["mport"] = ports
            if obfs_pw:
                p["obfs"] = "salamander"
                p["obfs-password"] = obfs_pw
            hy2.append(f"hysteria2://{q(h['password'])}@{h['server']}:{port}?"
                       + urllib.parse.urlencode(p) + f"#{q(name)}")
            cp = {"name": name, "type": "hysteria2", "server": h["server"], "port": int(port),
                  "password": h["password"], "sni": sni,
                  "skip-cert-verify": bool(h.get("tls_insecure"))}
            if ports:
                cp["ports"] = ports
            if obfs_pw:
                cp["obfs"] = "salamander"
                cp["obfs-password"] = obfs_pw
            clash.append(cp)

            hy_sb = {
                "type": "hysteria2", "tag": name, "server": h["server"],
                "server_port": int(port), "password": h["password"],
                "tls": {"enabled": True, "server_name": sni,
                        "insecure": bool(h.get("tls_insecure"))},
            }
            if ports:
                hy_sb["server_ports"] = [str(ports).replace("-", ":")]
            if obfs_pw:
                hy_sb["obfs"] = {"type": "salamander", "password": obfs_pw}
            sb.append(hy_sb)
            recs.append({"name": name, "proto": "hysteria2", "tag": nid, **h})

        # ---------- WireGuard ----------
        w = nd.get("wireguard")
        if w:
            name = f"{label}-WG"
            addr = w.get("local_address") or "10.0.0.2/32"
            wg.append(
                f"## {name}\n[Interface]\nPrivateKey = {w['private_key']}\n"
                f"Address = {addr}\nMTU = {w.get('mtu', 1420)}\n\n"
                f"[Peer]\nPublicKey = {w['peer_public_key']}\n"
                f"Endpoint = {w['server']}:{w['server_port']}\n"
                f"AllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n"
            )
            clash.append({
                "name": name, "type": "wireguard", "server": w["server"],
                "port": w["server_port"], "private-key": w["private_key"],
                "public-key": w["peer_public_key"], "ip": addr.split("/")[0], "udp": True,
            })
            sb.append({
                "type": "wireguard", "tag": name,
                "address": [addr], "private_key": w["private_key"],
                "mtu": w.get("mtu", 1420),
                "peers": [{"address": w["server"], "port": w["server_port"],
                           "public_key": w["peer_public_key"]}],
            })
            recs.append({"name": name, "proto": "wireguard", "tag": nid, **w})

    return vless, hy2, wg, clash, sb, recs


def default_out():
    """GitHub Actions / 仓库根目录输出。"""
    return os.path.dirname(os.path.abspath(__file__)) or "."


# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="DarkVPN 节点提取器（纯网络，无需 App / root / 登录）",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-o", "--out", default=None,
                    help="输出目录（默认当前目录）")
    ap.add_argument("--domains", action="store_true", help="只列出活动域名后退出")
    ap.add_argument("--stdout", action="store_true", help="节点链接打到 stdout，不写文件")
    ap.add_argument("-q", "--quiet", action="store_true", help="精简输出")
    args = ap.parse_args()
    args.out = args.out or default_out()

    def log(m):
        if not args.quiet:
            print(m, flush=True)

    log("DarkVPN 节点提取器")
    log("=" * 76)

    if args.domains:
        doms = get_domains()
        if not doms:
            sys.exit("获取域名失败")
        for d in sorted(doms, key=lambda x: -x.get("priority", 0)):
            log(f"  {d['url']:30s} priority={d.get('priority')}")
        return

    device_id = "vd-" + secrets.token_hex(24)
    log(f"device_id: {device_id}")

    data, base, err = fetch_config(device_id=device_id)
    if not data:
        sys.exit(f"获取配置失败: {err}")
    log(f"API: {base}   version: {data.get('version')}")

    nodes, auto = extract_nodes(data)
    labels = build_labels(data)
    log(f"节点: {len(nodes)} 个主机   自动选择池: {auto}")
    if not nodes:
        sys.exit("没有取到节点（可能需要登录或套餐）")

    vless, hy2, wg, clash, sb, recs = build_subscriptions(nodes, labels)

    if args.stdout:
        for line in vless + hy2:
            print(line)
        return

    try:
        os.makedirs(args.out, exist_ok=True)
    except OSError as e:
        sys.exit(f"无法创建输出目录 {args.out}: {e}")

    clash_cfg = {
        "proxies": clash,
        "proxy-groups": [
            {"name": "DarkVPN", "type": "select", "proxies": [p["name"] for p in clash]},
            {"name": "自动选择", "type": "url-test", "proxies": [p["name"] for p in clash],
             "url": "http://www.gstatic.com/generate_204", "interval": 300},
        ],
        "rules": ["MATCH,DarkVPN"],
    }
    singbox_cfg = {
        "log": {"level": "warn"},
        "dns": {"servers": [{"tag": "cf", "address": "https://1.1.1.1/dns-query"}]},
        "inbounds": [{
            "type": "mixed", "tag": "mixed-in",
            "listen": "127.0.0.1", "listen_port": 7890,
        }],
        "outbounds": sb + [{"type": "direct", "tag": "direct"}],
        "route": {"final": sb[0]["tag"] if sb else "direct"},
    }

    # 固定订阅文件名（带 dark，方便 raw 订阅）
    dark_lines = vless + hy2
    files = {
        "dark_nodes.txt": "\n".join(dark_lines) + ("\n" if dark_lines else ""),
        "nodes_all.json": json.dumps(recs, ensure_ascii=False, indent=2),
        "vless.txt": "\n".join(vless),
        "hysteria2.txt": "\n".join(hy2),
        "wireguard.txt": "\n\n".join(wg),
        "clash.yaml": json.dumps(clash_cfg, ensure_ascii=False, indent=2),
        "singbox.json": json.dumps(singbox_cfg, ensure_ascii=False, indent=2),
        "sub_base64.txt": base64.b64encode("\n".join(dark_lines).encode()).decode(),
    }

    log("")
    for fn, content in files.items():
        with open(os.path.join(args.out, fn), "w", encoding="utf-8") as f:
            f.write(content)
        log(f"  + {fn:22s} {len(content):>8,} bytes")

    log(f"\n完成：VLESS {len(vless)} | Hysteria2 {len(hy2)} | WireGuard {len(wg)}"
        f" | 合计 {len(recs)}")
    log(f"输出目录: {os.path.abspath(args.out)}")


if __name__ == "__main__":
    main()
