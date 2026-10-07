#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
小满 / Vela 全节点轮询（含 free 镜像），生成固定订阅文件。
输出（默认写到仓库内 subscription/ 目录，可用 OUT_DIR 覆盖）：
    subscription/xiaoman_nodes.json
    subscription/xiaoman_vless.txt

敏感信息通过环境变量注入（部署时用 GitHub Secrets），不要硬编码提交。
"""

import base64
import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlencode

import requests
import yaml
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============ 配置区（均可用环境变量覆盖，部署时走 GitHub Secrets） ============
TOKEN   = os.environ.get("XIAOMAN_TOKEN") or "925a5c96bd673bb2e3cf12def6d77ddc687b354be973b74650515bb24ed0c0d3"
KEY_B64 = os.environ.get("XIAOMAN_KEY_B64") or "xNLbV68V85fHLm8LfYsG5Uawao8ODo5wrSQD2qiGkjI="

# 输出目录：本地默认仓库内 subscription/，可通过 OUT_DIR 覆盖（如 Android 的 Download 目录）
OUT_DIR = Path(os.environ.get("OUT_DIR") or Path(__file__).resolve().parent / "subscription")

BASE    = os.environ.get("XIAOMAN_BASE") or "https://xiaomans.com/vela-api/api/v1"
PLATFORM = os.environ.get("XIAOMAN_PLATFORM") or "android"
ROUTING_MODE = os.environ.get("XIAOMAN_ROUTING") or "smart"

SLEEP_SELECT = float(os.environ.get("SLEEP_SELECT") or "0.3")
SLEEP_CONFIG = float(os.environ.get("SLEEP_CONFIG") or "0.3")
TIMEOUT = int(os.environ.get("TIMEOUT") or "30")
# =============================================================================


KEY = base64.b64decode(KEY_B64)
_UA = "小满 Android".encode("utf-8").decode("latin-1")

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "X-Vela-Client-Platform": PLATFORM,
    "X-Vela-App-Version": "1.14.0-alpha.21",
    "X-Vela-Build": "668",
    "X-Vela-Encrypted": "1",
    "X-App-Brand": "xiaoman",
    "User-Agent": _UA,
    "Accept": "application/json",
    "Accept-Language": "zh-CN",
}

S = requests.Session()
S.headers.update(HEADERS)


def _decrypt(env):
    if not env.get("encrypted"):
        return env
    return json.loads(AESGCM(KEY).decrypt(
        base64.b64decode(env["nonce"]),
        base64.b64decode(env["payload"]),
        None,
    ))


def api_get(path, **params):
    r = S.get(f"{BASE}{path}", params=params or None, timeout=TIMEOUT)
    r.raise_for_status()
    return _decrypt(r.json())


def api_post_plain(path, body):
    r = S.post(f"{BASE}{path}", json=body, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()


def select_node(node_id):
    try:
        resp = api_post_plain("/nodes/select", {"node_id": node_id})
        return bool(resp.get("ok")) and resp.get("selected_node_id") == node_id
    except Exception as e:
        print(f"    [!] select {node_id} 失败: {e}")
        return False


def fetch_singbox():
    return api_get("/config/singbox", platform=PLATFORM, routing_mode=ROUTING_MODE)


def outbound_to_vless(ob, name):
    tls = ob.get("tls") or {}
    real = tls.get("reality") or {}
    q = {
        "type": "tcp",
        "security": "reality" if real.get("enabled") else "tls",
        "sni": tls.get("server_name", ""),
        "fp": (tls.get("utls") or {}).get("fingerprint", ""),
        "pbk": real.get("public_key", ""),
        "sid": real.get("short_id", ""),
        "flow": ob.get("flow", ""),
    }
    query = urlencode({k: v for k, v in q.items() if v})
    return (f"vless://{ob['uuid']}@{ob['server']}:{ob['server_port']}"
            f"?{query}#{name}")


def outbound_to_clash(ob, name):
    """把一个 vless outbound 转成 Clash Meta 代理条目。"""
    tls = ob.get("tls") or {}
    real = tls.get("reality") or {}
    fp = (tls.get("utls") or {}).get("fingerprint") or "chrome"
    sni = tls.get("server_name", "")

    proxy = {
        "name": name,
        "type": "vless",
        "server": ob["server"],
        "port": ob["server_port"],
        "uuid": ob["uuid"],
        "network": "tcp",
        "udp": True,
    }
    if real.get("enabled"):
        proxy["tls"] = True
        if sni:
            proxy["servername"] = sni
        proxy["client-fingerprint"] = fp
        proxy["reality-opts"] = {
            "public-key": real.get("public_key", ""),
            "short-id": real.get("short_id", ""),
        }
    elif tls:
        proxy["tls"] = True
        if sni:
            proxy["servername"] = sni
        proxy["client-fingerprint"] = fp
        proxy["skip-cert-verify"] = True
    else:
        proxy["tls"] = False

    flow = ob.get("flow")
    if flow:
        proxy["flow"] = flow
    return proxy


def build_clash_config(proxies):
    """生成一份可直接导入 Clash Meta 的完整配置。"""
    names = [p["name"] for p in proxies]
    return {
        "mixed-port": 7890,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "external-controller": "127.0.0.1:9090",
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "🚀 节点选择",
                "type": "select",
                "proxies": ["♻️ 自动选择", "DIRECT"] + names,
            },
            {
                "name": "♻️ 自动选择",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "proxies": names,
            },
        ],
        "rules": [
            "GEOIP,CN,DIRECT",
            "MATCH,🚀 节点选择",
        ],
    }


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    print("[*] 拉取 /nodes ...")
    nodes = api_get("/nodes", refresh=1)
    items = nodes.get("items", [])

    # 不再过滤 ::free::xiaoman，全量轮询
    main_items = list(items)

    print(f"    条目总数: {len(main_items)}  当前选中: {nodes.get('selected_node_id')}")

    original_selected = nodes.get("selected_node_id")
    result = {
        "selected_node_id": original_selected,
        "countries": nodes.get("countries", []),
        "nodes_meta": main_items,
        "free_items_meta": nodes.get("free_items", []),
        "paid_items_meta": nodes.get("paid_items", []),
        "configs": {},
        "failed": [],
    }

    print("[*] 轮询节点 ...")
    for i, it in enumerate(main_items, 1):
        nid = it["id"]
        name = it.get("name") or nid

        if not select_node(nid):
            result["configs"][nid] = None
            result["failed"].append(nid)
            print(f"    [{i:>2}/{len(main_items)}] {nid:<32} 切换失败")
            time.sleep(SLEEP_SELECT)
            continue

        time.sleep(SLEEP_CONFIG)

        try:
            cfg = fetch_singbox()
        except Exception as e:
            cfg = None
            print(f"    [{i:>2}/{len(main_items)}] {nid:<32} 拉配置失败: {e}")

        if cfg:
            result["configs"][nid] = cfg
            vless = [o for o in cfg.get("outbounds", []) if o.get("type") == "vless"]
            tag = vless[0].get("tag") if vless else "?"
            print(f"    [{i:>2}/{len(main_items)}] {nid:<32} OK (tag={tag})")
        else:
            result["configs"][nid] = None
            result["failed"].append(nid)

        time.sleep(SLEEP_SELECT)

    if original_selected:
        try:
            select_node(original_selected)
            print(f"[*] 已还原选中节点: {original_selected}")
        except Exception:
            pass

    jp = OUT_DIR / "xiaoman_nodes.json"
    jp.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[+] {jp}")

    uris = []
    clash_proxies = []
    for it in main_items:
        nid = it["id"]
        cfg = result["configs"].get(nid)
        if not cfg:
            continue
        label = it.get("name") or nid
        if "::free::xiaoman" in nid:
            label = f"{label} [free]"
        for ob in cfg.get("outbounds", []):
            if ob.get("type") == "vless":
                uris.append(outbound_to_vless(ob, label))
                clash_proxies.append(outbound_to_clash(ob, label))

    up = OUT_DIR / "xiaoman_vless.txt"
    up.write_text("\n".join(uris) + ("\n" if uris else ""), encoding="utf-8")
    print(f"[+] {up}  ({len(uris)} 条)")

    # ---- Clash 订阅 ----
    cp_path = OUT_DIR / "clash_proxies.yaml"
    cp_path.write_text(
        "# Clash Meta / Mihomo Proxies (小满/Vela)\n" + yaml.safe_dump(
            {"proxies": clash_proxies}, allow_unicode=True,
            sort_keys=False, default_flow_style=False),
        encoding="utf-8")
    cf_path = OUT_DIR / "clash.yaml"
    cf_path.write_text(yaml.safe_dump(
        build_clash_config(clash_proxies), allow_unicode=True,
        sort_keys=False, default_flow_style=False), encoding="utf-8")
    print(f"[+] {cp_path}  ({len(clash_proxies)} 条)")
    print(f"[+] {cf_path}")

    ok = len(main_items) - len(result["failed"])
    print(f"\n成功: {ok}/{len(main_items)}")
    if result["failed"]:
        print("失败:", ", ".join(result["failed"]))


if __name__ == "__main__":
    try:
        main()
    except requests.HTTPError as e:
        code = e.response.status_code if e.response is not None else "?"
        print(f"[!] HTTP {code}: {e}", file=sys.stderr)
        if code == 401:
            print("    → token 过期，重新登录小满客户端并更新 XIAOMAN_TOKEN", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(1)
