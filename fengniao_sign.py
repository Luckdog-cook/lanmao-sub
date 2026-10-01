#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" 蜂鸟加速器 - 自动注册并拉取节点解密（GitHub Actions 增强版） 功能： - 失败重试 - 只保留成功节点 - 自动生成 Clash Meta 配置 - Base64 订阅 + 明文链接 + JSON - VIP 到期前自动换号（不依赖猜有效期，直接用 API 返回的 vipEndTime） 用法: python fengniao_sign.py python fengniao_sign.py --serial=你的序列号 python fengniao_sign.py --delay=3.0 python fengniao_sign.py --force-new # 强制换新号 环境变量: FENGNIAO_SERIAL 优先使用此序列号 FENGNIAO_FORCE_NEW=1 等同于 --force-new """
import base64
import hashlib
import json
import os
import sys
import time
import uuid
from urllib.parse import quote
from urllib.request import Request, urlopen

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

API = "https://api.go01.top/proxy"
AES_IV = b"A-16-Byte-String"
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "./")

# 账号信息持久化文件（serial + vipEndTime）
ACCOUNT_FILE = os.path.join(OUTPUT_DIR, "fengniao_account.json")

# VIP 过期前多久换号（秒）
# 设 1 小时 = 3600 秒：如果距离 vipEndTime 不到 1 小时，就提前换号
# 这样即使 Actions 每 3 小时跑一次，也不会出现"刚好过期"的空窗
VIP_RENEW_MARGIN = 3600


def md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()

def build_decrypt_key(ts_str: str, rid: str, token: str) -> str:
    if int(ts_str) % 2 == 0:
        seq = [("rid", 16), ("rid", 8), ("ts", -3), ("rid", 12), ("rid", 26), ("ts", -2), ("rid", 2), ("rid", 18),
               ("tok", 16), ("tok", 8), ("ts", -3), ("tok", 12), ("tok", 26), ("ts", -2), ("tok", 2), ("tok", 18)]
    else:
        seq = [("rid", 5), ("rid", 11), ("ts", -2), ("rid", 8), ("rid", 27), ("ts", -1), ("rid", 9), ("rid", 21),
               ("tok", 5), ("tok", 11), ("ts", -2), ("tok", 8), ("tok", 27), ("ts", -1), ("tok", 9), ("tok", 21)]
    out = []
    for src, idx in seq:
        s = rid if src == "rid" else (ts_str if src == "ts" else token)
        out.append(s[idx])
    return "".join(out)

def decrypt_node(content_b64: str, ts_str: str, rid: str, token: str):
    key = build_decrypt_key(ts_str, rid, token)
    aes = AES.new(key.encode(), AES.MODE_CBC, AES_IV)
    try:
        pt = unpad(aes.decrypt(base64.b64decode(content_b64)), 16)
        return pt.decode("utf-8", errors="replace"), key
    except Exception:
        return None, key

def build_key(ts_str: str, rid: str, token: str) -> str:
    L = len(ts_str)
    ts2 = ts_str[L - 2]
    if int(ts_str) % 2 == 0:
        k8 = rid[16] + rid[8] + ts_str[L - 3] + rid[12] + rid[26] + ts2 + rid[2] + rid[18]
    else:
        k8 = rid[5] + rid[11] + ts2 + rid[8] + rid[27] + ts_str[L - 1] + rid[9] + rid[21]
    idx = int(ts2)
    k8 += (token[idx] if token else rid[idx])
    return k8

def gen_serial() -> str:
    return base64.b64encode(uuid.uuid4().bytes + uuid.uuid4().bytes[:16]).decode()

def make_sign(params: dict, token: str, serial: str) -> tuple:
    now = int(time.time() * 1000)
    rid = uuid.uuid4().hex
    p = dict(params)
    p.update({
        "version": "v3.1.1",
        "rankVersion": "10",
        "serialNumber": serial,
        "requestTimestamp": str(now),
        "requestId": rid,
        "clientType": "Android",
        "promoteChannel": "S100",
        "clientModel": "XT2201-2",
    })
    if token:
        p["token"] = token
    ps = "&".join(f"{k}={p[k]}" for k in sorted(p))
    key = build_key(str(now), rid, token)
    sign = md5(ps + key)
    return p, sign

def request(path: str, params: dict, token: str = "", serial: str = "") -> dict:
    p, sign = make_sign(params, token, serial)
    boundary = uuid.uuid4().hex
    parts = []
    for k, v in {**p, "sign": sign}.items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n')
    data = ("".join(parts) + f"--{boundary}--\r\n").encode()
    req = Request(f"{API}{path}", data=data, method="POST")
    req.add_header("User-Agent", "okhttp-okgo/jeasonlzy")
    req.add_header("Accept-Language", "zh-CN,zh;q=0.8")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    with urlopen(req, timeout=15) as r:
        return {
            "status": r.status,
            "body": r.read().decode("utf-8", "replace"),
            "requestTimestamp": p["requestTimestamp"],
            "requestId": p["requestId"]
        }

def to_trojan_link(plain: str, name: str = "") -> str:
    if not plain:
        return ""
    parts = [p.strip() for p in plain.split(',')]
    if len(parts) < 5:
        return ""
    proto, server, port, password, method = parts[0], parts[1], parts[2], parts[3], parts[4]
    if proto.lower() != "trojan":
        return ""
    link = f"trojan://{password}@{server}:{port}?encryption={method}"
    if name:
        link += f"#{quote(name)}"
    return link

def parse_trojan_node(plain: str, name: str) -> dict | None:
    """解析明文，返回 Clash 可用的节点字典"""
    if not plain:
        return None
    parts = [p.strip() for p in plain.split(',')]
    if len(parts) < 5:
        return None
    proto, server, port, password, method = parts[0], parts[1], parts[2], parts[3], parts[4]
    if proto.lower() != "trojan":
        return None
    try:
        port = int(port)
    except ValueError:
        return None
    return {
        "name": name or f"{server}:{port}",
        "type": "trojan",
        "server": server,
        "port": port,
        "password": password,
        "udp": True,
        "skip-cert-verify": True,   # 很多客户端需要
    }

def generate_clash_config(proxies: list) -> str:
    """生成简单可用的 Clash Meta 配置"""
    if not proxies:
        return ""

    proxy_names = [p["name"] for p in proxies]

    # 用 yaml 手动拼接，避免额外依赖
    lines = [
        "mixed-port: 7890",
        "allow-lan: true",
        "mode: rule",
        "log-level: info",
        "external-controller: 127.0.0.1:9090",
        "",
        "proxies:",
    ]
    for p in proxies:
        lines.append(f" - name: \"{p['name']}\"")
        lines.append(f" type: {p['type']}")
        lines.append(f" server: {p['server']}")
        lines.append(f" port: {p['port']}")
        lines.append(f" password: \"{p['password']}\"")
        lines.append(f" udp: true")
        lines.append(f" skip-cert-verify: true")
        lines.append("")

    lines.extend([
        "proxy-groups:",
        " - name: PROXY",
        " type: select",
        " proxies:",
    ])
    for name in proxy_names:
        lines.append(f" - \"{name}\"")
    lines.append(" - DIRECT")
    lines.append("")
    lines.extend([
        " - name: AUTO",
        " type: url-test",
        " url: http://www.gstatic.com/generate_204",
        " interval: 300",
        " tolerance: 50",
        " proxies:",
    ])
    for name in proxy_names:
        lines.append(f" - \"{name}\"")
    lines.append("")
    lines.extend([
        "rules:",
        " - GEOIP,CN,DIRECT",
        " - MATCH,PROXY",
    ])
    return "\n".join(lines)


# ============================================================
# 账号持久化：存取 serial + vipEndTime
# ============================================================

def save_account(serial: str, vip_end: int = 0, account: str = "", extra: dict = None):
    """保存账号信息到 JSON 文件"""
    data = {
        "serial": serial,
        "vipEndTime": vip_end,
        "account": account,
        "saved_at": int(time.time()),
    }
    if extra:
        data.update(extra)
    try:
        with open(ACCOUNT_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"保存账号信息失败: {e}")

def load_account() -> dict:
    """读取已有账号信息，返回 {} 表示没有"""
    try:
        with open(ACCOUNT_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def is_vip_expiring_soon(vip_end_ts: int, margin: int = VIP_RENEW_MARGIN) -> bool:
    """ 判断 VIP 是否快过期了。 vip_end_ts 是毫秒时间戳（蜂鸟 API 返回的 vipEndTime） 返回 True 表示距离过期不到 margin 秒，该换号了 """
    if not vip_end_ts or vip_end_ts <= 0:
        return True   # 没有有效时间，需要换号
    # API 返回的 vipEndTime 是毫秒，转成秒
    vip_end_sec = vip_end_ts / 1000 if vip_end_ts > 1e12 else vip_end_ts
    now = time.time()
    remain = vip_end_sec - now
    return remain < margin

def format_vip_remain(vip_end_ts: int) -> str:
    """格式化 VIP 剩余时间"""
    if not vip_end_ts or vip_end_ts <= 0:
        return "无有效时间"
    vip_end_sec = vip_end_ts / 1000 if vip_end_ts > 1e12 else vip_end_ts
    remain = vip_end_sec - time.time()
    if remain <= 0:
        return "已过期"
    h = int(remain // 3600)
    m = int((remain % 3600) // 60)
    return f"还剩 {h}h{m}m"


def fetch_all_nodes(serial: str, delay: float = 2.0, max_login_retry: int = 2) -> tuple:
    """ 拉取节点。返回 (token, vip_end_ts, account_name) vip_end_ts 用于判断过期，0 表示没拿到 """
    token = ""
    vip_end = 0
    account_name = ""
    register_gift = ""

    for login_attempt in range(1, max_login_retry + 1):
        print(f"== server/info (attempt {login_attempt}) ==")
        try:
            request("/server/info", {}, serial=serial)
        except Exception as e:
            print(f"server/info 失败: {e}")

        print("== user/auto/login ==")
        try:
            r = request("/user/auto/login", {}, serial=serial)
            body = json.loads(r["body"])
        except Exception as e:
            print(f"登录请求失败: {e}")
            if login_attempt < max_login_retry:
                time.sleep(5)
                continue
            return "", 0, ""

        if body.get("code") != 0:
            print("登录失败:", r["body"])
            if login_attempt < max_login_retry:
                time.sleep(5)
                continue
            return "", 0, ""

        if "data" not in body or "token" not in body.get("data", {}):
            print("风控提示: 服务端返回 code:0 但未发放 token（新号注册频繁被临时风控）。")
            print(" 建议使用 --serial 或环境变量 FENGNIAO_SERIAL 固定已有账号。")
            if login_attempt < max_login_retry:
                time.sleep(8)
                continue
            return "", 0, ""

        token = body["data"]["token"]
        register_gift = body["data"].get("registerGift", "")
        print(f"token: {token} (registerGift: {register_gift})")
        break

    if not token:
        return "", 0, ""

    print("== user/my/info ==")
    try:
        r = request("/user/my/info", {}, token=token, serial=serial)
        info = json.loads(r["body"])["data"]
        vip_end = info.get("vipEndTime", 0) or 0
        account_name = info.get("account", "") or ""
        print(f" 账号 {account_name} vipEndTime={vip_end} ({format_vip_remain(vip_end)}) recommenderId={info.get('recommenderId')}")
    except Exception:
        pass

    # 即使没拿到 vipEndTime，也把 serial + 已知信息存下来
    save_account(serial, vip_end, account_name, {"registerGift": register_gift})

    print("== user/fetch/node/list ==")
    r = request("/user/fetch/node/list", {"vipType": "vip"}, token=token, serial=serial)
    try:
        nodes = json.loads(r["body"])["data"]
    except Exception:
        print("获取节点列表失败:", r["body"][:200])
        return token, vip_end, account_name

    print(f"共 {len(nodes)} 个节点（详情间隔 {delay}s）")

    success_nodes = []      # 只保留成功解密的
    node_links = []
    clash_proxies = []

    for i, node in enumerate(nodes):
        name = node.get("name", f"node-{i}")
        content = ""
        pt = None
        key = ""

        for attempt in range(3):  # 单个节点重试 3 次
            try:
                r = request("/user/fetch/node/detail", {"nodeId": node["id"]}, token=token, serial=serial)
                content = json.loads(r["body"])["data"]["content"]
                break
            except Exception as e:
                if attempt < 2:
                    print(f" {name}: 重试 {attempt+1}/2 ...")
                    time.sleep(delay * 1.5)
                else:
                    print(f" {name}: 最终失败 {str(e)[:80]}")
                    content = ""

        if content:
            pt, key = decrypt_node(content, r["requestTimestamp"], r["requestId"], token)
            print(f" {name:12s} key={key} -> {pt if pt else 'FAIL'}")

        if pt:
            # 只保留成功节点
            node["_plain"] = pt
            success_nodes.append(node)

            link = to_trojan_link(pt, name)
            if link:
                node_links.append(link)

            clash_node = parse_trojan_node(pt, name)
            if clash_node:
                clash_proxies.append(clash_node)

        if i < len(nodes) - 1:
            time.sleep(delay)

    print(f"\n成功解密节点: {len(success_nodes)} / {len(nodes)}")

    # ========== 保存文件 ==========
    # 1. JSON（只含成功节点）
    json_path = os.path.join(OUTPUT_DIR, "fengniao_nodes.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(success_nodes, f, ensure_ascii=False, indent=2)
    print(f"JSON 已保存至 {json_path}")

    # 2. 明文 Trojan 链接
    links_path = os.path.join(OUTPUT_DIR, "节点链接.txt")
    with open(links_path, "w", encoding="utf-8") as f:
        f.write("\n".join(node_links))
    print(f"Trojan 链接已保存至 {links_path}（共 {len(node_links)} 条）")

    # 3. Base64 订阅
    if node_links:
        b64 = base64.b64encode("\n".join(node_links).encode("utf-8")).decode("utf-8")
        sub_path = os.path.join(OUTPUT_DIR, "sub.txt")
        with open(sub_path, "w", encoding="utf-8") as f:
            f.write(b64)
        print(f"Base64 订阅已保存至 {sub_path}")

    # 4. Clash Meta 配置
    if clash_proxies:
        clash_content = generate_clash_config(clash_proxies)
        clash_path = os.path.join(OUTPUT_DIR, "clash.yaml")
        with open(clash_path, "w", encoding="utf-8") as f:
            f.write(clash_content)
        print(f"Clash 配置已保存至 {clash_path}（共 {len(clash_proxies)} 个节点）")

    return token, vip_end, account_name


def main():
    args = sys.argv[1:]
    serial = next((a.split("=", 1)[1] for a in args if a.startswith("--serial=")), "")
    delay = float(next((a.split("=", 1)[1] for a in args if a.startswith("--delay=")), "2.5"))
    force_new = "--force-new" in args or os.environ.get("FENGNIAO_FORCE_NEW", "").strip() in ("1", "true", "yes")

    # ====== 决定用哪个 serial ======
    if force_new:
        print("🔧 强制换新号")
        serial = gen_serial()
        print(f"生成新序列号: {serial}")
    elif not serial:
        # 没传 serial，先看有没有已保存的账号
        acct = load_account()
        saved_serial = acct.get("serial", "")
        saved_vip = acct.get("vipEndTime", 0)

        if saved_serial:
            serial = saved_serial
            if is_vip_expiring_soon(saved_vip):
                print(f"📖 已有账号 VIP {format_vip_remain(saved_vip)}，即将过期 → 自动换新号")
                serial = gen_serial()
                print(f"生成新序列号: {serial}")
            else:
                print(f"📖 复用已有账号，serial={serial[:24]}... VIP {format_vip_remain(saved_vip)}")
        else:
            serial = os.environ.get("FENGNIAO_SERIAL", "").strip()
            if not serial:
                serial = gen_serial()
                print(f"生成新序列号: {serial} （新账号）")
            else:
                print(f"使用环境变量 serial: {serial}")
    else:
        print(f"使用指定序列号: {serial}")

    # ====== 拉取节点 ======
    token, vip_end, account_name = fetch_all_nodes(serial, delay)

    if token:
        print(f"\n✅ 注册 + 节点拉取完成。VIP {format_vip_remain(vip_end)}")
    else:
        print("\n❌ 本次未成功获取节点。")
        # 如果是复用旧号失败的，可能是被风控了，清掉账号文件让下次自动换号
        if not force_new:
            acct = load_account()
            if acct.get("serial") == serial:
                print("🧹 清理旧账号信息，下次自动换新号")
                try:
                    os.remove(ACCOUNT_FILE)
                except Exception:
                    pass
        sys.exit(1)

if __name__ == "__main__":
    main()
