#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动拉取 fluxyun 节点（UA 必须为 feivpn）
"""
import base64
import os
import urllib.request

# ============ 配置 ============
SUBSCRIBE_URL = "https://api.fluxyun.com/xiaofeixia?token=49226efc81a5652467500037eb0ee3a9"
UA = "feivpn"
OUTPUT_LINKS = "节点链接.txt"
OUTPUT_SUB = "sub.txt"
# ==============================

def fetch_nodes():
    req = urllib.request.Request(SUBSCRIBE_URL, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=20) as resp:
        content = resp.read().decode("utf-8", errors="ignore").strip()

    # 判断是否是 base64
    try:
        decoded = base64.b64decode(content).decode("utf-8", errors="ignore")
        if "://" in decoded:
            content = decoded
    except Exception:
        pass

    links = [line.strip() for line in content.splitlines() if "://" in line]
    print(f"成功获取 {len(links)} 条节点")
    return links

def main():
    links = fetch_nodes()
    if not links:
        print("未获取到节点，请检查 token 或网络")
        return

    # 明文链接
    with open(OUTPUT_LINKS, "w", encoding="utf-8") as f:
        f.write("\n".join(links))
    print(f"已保存: {OUTPUT_LINKS}")

    # Base64 订阅
    b64 = base64.b64encode("\n".join(links).encode("utf-8")).decode()
    with open(OUTPUT_SUB, "w", encoding="utf-8") as f:
        f.write(b64)
    print(f"已保存: {OUTPUT_SUB}")

if __name__ == "__main__":
    main()
