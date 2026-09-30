#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
guangying.py - 光影VPN 自动节点猎手（GitHub 自动化版）
===========================
用途: 全自动扫描 + 生成固定订阅 guangying.txt + guangying.yaml
"""

import argparse, base64, concurrent.futures as cf, os, random, re, shutil, subprocess, sys, tempfile, time
from collections import defaultdict

TARGET   = "43.159.7.5"
METHOD   = "aes-128-gcm"
PASSWORD = "2wsxcde3"
KNOWN    = [21574, 31597, 35933, 36735, 40322, 49277, 53907]
TRACE    = "https://www.cloudflare.com/cdn-cgi/trace"
OUTDIR   = os.path.expanduser("~/gy-hunter")
DEADLIST = os.path.join(OUTDIR, "dead_ports.txt")

def sh(cmd, timeout=60):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)

def need(binname, pkg):
    if not shutil.which(binname):
        print(f"[!] 缺 {binname}，尝试 apt install {pkg} …")
        sh(f"apt-get install -y -qq {pkg}", timeout=180)
        if not shutil.which(binname):
            sys.exit(f"[x] 无法安装 {binname}，请手动安装 {pkg}")

def get_ss_bin():
    for bin_name in ("ss-local", "sslocal", "clash"):
        if shutil.which(bin_name):
            return bin_name
    sys.exit("[x] 缺 ss-local/sslocal，请安装 shadowsocks-libev 或 shadowsocks-rust")

def discover_ports(rate=600):
    need("masscan", "masscan")
    need("nmap", "nmap")
    ports = set()
    with tempfile.NamedTemporaryFile(delete=False) as f1, tempfile.NamedTemporaryFile(delete=False) as f2, tempfile.NamedTemporaryFile(delete=False) as f3:
        p1, p2, p3 = f1.name, f2.name, f3.name

    print("[*] masscan 第一轮 (高频)…")
    sh(f"masscan -p1-65535 {TARGET} --rate {rate} -oL {p1}", timeout=600)
    for line in open(p1, errors="ignore"):
        m = re.match(r"open tcp (\d+)", line)
        if m: ports.add(int(m.group(1)))

    print("[*] masscan 第二轮 (低速对冲)…")
    sh(f"masscan -p1-65535 {TARGET} --rate {max(rate//3,100)} -oL {p2}", timeout=900)
    n2 = set()
    for line in open(p2, errors="ignore"):
        m = re.match(r"open tcp (\d+)", line)
        if m: n2.add(int(m.group(1)))
    ports |= n2

    print("[*] masscan 第三轮 (防丢包)…")
    sh(f"masscan -p1-65535 {TARGET} --rate {max(rate//5,50)} -oL {p3}", timeout=1200)
    n3 = set()
    for line in open(p3, errors="ignore"):
        m = re.match(r"open tcp (\d+)", line)
        if m: n3.add(int(m.group(1)))
    ports |= n3

    # nmap 最终兜底
    print("[*] nmap 最终兜底")
    sh(f"nmap -p1-65535 --host-timeout 3s -T4 -Pn {TARGET} -oG -", timeout=1200)
    for line in open("nmap_output", errors="ignore"):
        m = re.match(r"Host: .+? (\d+)/open", line)
        if m: ports.add(int(m.group(1)))
    if os.path.exists("nmap_output"):
        os.unlink("nmap_output")

    return sorted(ports)

def ss_handshake(port, timeout=9, ss_bin=None):
    lp = random.randint(20000, 59999)
    bin_name = os.path.basename(ss_bin or "ss-local")
    if "clash" in bin_name.lower():
        cmd = [ss_bin or "clash", "-s", f"{TARGET}:{port}", "-b", f"127.0.0.1:{lp}", "-m", METHOD, "-k", PASSWORD]
    elif "sslocal" in bin_name and "libev" not in (ss_bin or ""):
        cmd = [ss_bin or "sslocal", "-s", f"{TARGET}:{port}", "-b", f"127.0.0.1:{lp}", "-m", METHOD, "-k", PASSWORD]
    else:
        cmd = [ss_bin or "ss-local", "-s", TARGET, "-p", str(port), "-l", str(lp), "-m", METHOD, "-k", PASSWORD, "-t", "5"]

    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(0.4)
        r = subprocess.run(["curl", "-s", "--socks5-hostname", f"127.0.0.1:{lp}", "-m", str(timeout), TRACE],
                           capture_output=True, text=True, timeout=timeout + 3)
        loc = ip = None
        for line in r.stdout.splitlines():
            if line.startswith("loc="): loc = line[4:].strip()
            if line.startswith("ip="):  ip  = line[3:].strip()
        if loc:
            return (loc, ip)
    except Exception:
        pass
    finally:
        p.terminate()
        try: p.wait(timeout=2)
        except: p.kill()
    return None

def geo_detail(port, ss_bin=None):
    lp = random.randint(20000, 59999)
    bin_name = os.path.basename(ss_bin or "ss-local")
    if "clash" in bin_name.lower():
        cmd = [ss_bin or "clash", "-s", f"{TARGET}:{port}", "-b", f"127.0.0.1:{lp}", "-m", METHOD, "-k", PASSWORD]
    elif "sslocal" in bin_name and "libev" not in (ss_bin or ""):
        cmd = [ss_bin or "sslocal", "-s", f"{TARGET}:{port}", "-b", f"127.0.0.1:{lp}", "-m", METHOD, "-k", PASSWORD]
    else:
        cmd = [ss_bin or "ss-local", "-s", TARGET, "-p", str(port), "-l", str(lp), "-m", METHOD, "-k", PASSWORD, "-t", "5"]

    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(0.4)
        r = subprocess.run(["curl", "-s", "--socks5-hostname", f"127.0.0.1:{lp}", "-m", "8", "http://ip-api.com/line/?fields=country,city,query"],
                           capture_output=True, text=True, timeout=12)
        parts = [x.strip() for x in r.stdout.splitlines() if x.strip()]
        if len(parts) >= 3:
            return parts
    except:
        pass
    finally:
        p.terminate()
        try: p.wait(timeout=2)
        except: p.kill()
    return None

FLAG = {"US":"🇺🇸","HK":"🇭🇰","JP":"🇯🇵","DE":"🇩🇪","TW":"🇹🇼","SG":"🇸🇬","KR":"🇰🇷"}
CODE = {"United States":"US","Hong Kong":"HK","Japan":"JP","Germany":"DE","Taiwan":"TW","Singapore":"SG","South Korea":"KR"}
ABBR = {"US":"US","HK":"HK","JP":"JP","DE":"DE","TW":"TW","SG":"SG","KR":"KR"}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fast", action="store_true")
    ap.add_argument("--ports", help="指定端口")
    ap.add_argument("--recheck", action="store_true")
    ap.add_argument("--workers", type=int, default=60)
    a = ap.parse_args()

    os.makedirs(OUTDIR, exist_ok=True)
    ss_bin = get_ss_bin()
    need("curl", "curl")

    if a.recheck:
        ports = set()
        for f in (os.path.expanduser("~/gy-nodes/nodes.txt"), os.path.join(os.path.dirname(os.path.abspath(__file__)), "nodes.txt")):
            try:
                for line in open(f):
                    m = re.search(r":(\d+)(?:#|$)", line)
                    if m: ports.add(int(m.group(1)))
            except: pass
        for f in (os.path.expanduser("~/gy-nodes/clash.yaml"), os.path.join(os.path.dirname(os.path.abspath(__file__)), "clash.yaml")):
            try:
                with open(f) as ff:
                    for line in ff:
                        if line.strip().startswith("port:"):
                            ports.add(int(line.split(":", 1)[1].strip()))
            except: pass
        ports = sorted(ports)
    elif a.ports:
        ports = sorted(set(int(x) for part in a.ports.split(",") for x in (part.split("-") if "-" in part else [part])))
    elif a.fast:
        ports = KNOWN[:]
    else:
        ports = discover_ports()

    print(f"[*] 待试端口 {len(ports)} 个 (并发 {a.workers})")

    hits, tried = [], 0
    with cf.ThreadPoolExecutor(a.workers) as ex:
        futs = {ex.submit(ss_handshake, p, 9, ss_bin): p for p in ports}
        for fu in cf.as_completed(futs):
            tried += 1
            p = futs[fu]
            if res := fu.result():
                hits.append((p, res[0], res[1]))
                print(f"  ✅ {p}  loc={res[0]}  exit={res[1]}")
            if tried % 200 == 0:
                print(f"  … {tried}/{len(ports)}")

    if not hits:
        print("[x] 零命中")
        return

    final = []
    for port, loc, ip in sorted(hits):
        g = geo_detail(port, ss_bin)
        country, city, real_ip = (g + [None, None, None])[:3] if g else (loc, "?", ip)
        flag = FLAG.get(country[:2] if country else "", "")
        final.append((port, country or "?", city or "?", real_ip or ip or "?", flag))

    print("\n============ 可用节点 ============")
    print(f"{'端口':<8}{'国家':<14}{'城市':<18}{'出口IP'}")
    for p, c, ci, ip, f in final:
        print(f"{p:<8}{f}{c:<12}{ci:<16}{ip}")

    # ==================== 生成固定订阅 guangying.txt ====================
    nodes_file = os.path.expanduser("~/gy-nodes/guangying.txt")
    os.makedirs(os.path.dirname(nodes_file), exist_ok=True)

    with open(nodes_file, "w") as f:
        f.write("# --- 光影VPN guangying.txt --- " + time.strftime("%Y-%m-%d %H:%M") + " ---\n")
        for port, country, city, ip, flag in final:
            cc = CODE.get(country, country[:2])
            tag = f"{ABBR.get(cc, cc)}-{city.replace(' ','')}-{port}"
            f.write(f"ss://{base64.b64encode(f'{METHOD}:{PASSWORD}'.encode()).decode().rstrip('=')}={TARGET}:{port}#{tag}\n")

    print(f"\n[+] 固定订阅已生成: {nodes_file}（手机导入用）")

    # ==================== Clash 导出 ====================
    clash_file = os.path.expanduser("~/gy-nodes/guangying.yaml")
    if not os.path.exists(os.path.dirname(clash_file)):
        clash_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "guangying.yaml")

    with open(clash_file, "w") as f:
        f.write("port: 7890\nsocks-port: 7891\nallow-lan: true\nmode: rule\nlog-level: info\nexternal-controller: 127.0.0.1:9090\n")
        f.write("proxy-providers:\n")
        for port, country, city, ip, flag in final:
            cc = CODE.get(country, country[:2])
            tag = f"{ABBR.get(cc, cc)}-{city.replace(' ','')}-{port}"
            f.write(f"  {tag}:\n    type: ss\n    server: {TARGET}\n    port: {port}\n    cipher: {METHOD}\n    password: {PASSWORD}\n    obfs: none\n    udp: true\n\n")
    print(f"[+] Clash 配置文件已生成: {clash_file}")

if __name__ == "__main__":
    main()
