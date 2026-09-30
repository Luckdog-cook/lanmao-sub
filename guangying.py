#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""光影VPN 节点猎手 v6.2 -- GitHub Actions 云端版（支持 ss-local + clash 双引擎）"""

import argparse, base64, concurrent.futures as cf, os, random, re, shutil, subprocess, sys, time, tempfile

TARGET   = "43.159.7.5"
METHOD   = "aes-128-gcm"
PASSWORD = "2wsxcde3"
KNOWN    = [21574, 31597, 35933, 36735, 40322, 49277, 53907]
TRACE    = "https://www.cloudflare.com/cdn-cgi/trace"
OUTDIR   = os.path.dirname(os.path.abspath(__file__))

def sh(cmd, timeout=300):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)

def need(binname, pkg):
    if not shutil.which(binname):
        sh(f"apt-get update -qq && apt-get install -y -qq {pkg}", timeout=600)
        if not shutil.which(binname):
            sys.exit(f"[x] 无法安装 {binname}")

def get_proxy_bin():
    """优先 ss-local/sslocal，其次 clash"""
    for b in ("ss-local", "sslocal"):
        if shutil.which(b):
            return ("ss", b)
    if shutil.which("clash"):
        return ("clash", "clash")
    sys.exit("[x] 无 ss 客户端也无 clash，请安装任一")

def discover_ports():
    if os.environ.get("GITHUB_ACTIONS") == "true":
        return sorted(set(KNOWN + [36736, 49278, 53908]))
    need("masscan", "masscan")
    ports = set()
    sh(f"masscan -p1-65535 {TARGET} --rate 200 -oL /tmp/m1", timeout=600)
    for line in open("/tmp/m1", errors="ignore"):
        m = re.match(r"open tcp (\d+)", line)
        if m: ports.add(int(m.group(1)))
    return sorted(ports)

def make_clash_config(port, lp):
    """为单个端口生成临时 clash 配置（真正可启动的格式）"""
    return f"""mixed-port: {lp}
allow-lan: false
mode: global
log-level: silent
proxies:
  - name: probe
    type: ss
    server: {TARGET}
    port: {port}
    cipher: {METHOD}
    password: {PASSWORD}
    udp: true
proxy-groups:
  - name: PROXY
    type: select
    proxies: [probe]
rules:
  - MATCH,PROXY
"""

def handshake(port, timeout=9, engine=None, ss_bin=None):
    lp = random.randint(20000, 59999)
    proc = None
    tmp_cfg = None
    try:
        if engine == "clash":
            # clash 必须用 -f 指定配置文件启动，不能像 ss-local 那样传 -s/-p
            fd, tmp_cfg = tempfile.mkstemp(suffix=".yml")
            with os.fdopen(fd, "w") as f:
                f.write(make_clash_config(port, lp))
            # 注意：clash 监听 mixed-port，即 lp 端口同时支持 http/socks
            cmd = [ss_bin, "-f", tmp_cfg]
            proxy_url = f"http://127.0.0.1:{lp}"
            curl_cmd = ["curl", "-s", "-x", proxy_url, "-m", str(timeout), TRACE]
        else:
            # ss-local 走 socks5
            cmd = [ss_bin, "-s", TARGET, "-p", str(port), "-l", str(lp),
                   "-m", METHOD, "-k", PASSWORD, "-t", "5"]
            curl_cmd = ["curl", "-s", "--socks5-hostname",
                        f"127.0.0.1:{lp}", "-m", str(timeout), TRACE]
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.2)  # clash 启动比 ss-local 慢，多等一会
        r = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=timeout + 3)
        loc = ip = None
        for line in r.stdout.splitlines():
            if line.startswith("loc="): loc = line[4:].strip()
            if line.startswith("ip="):  ip  = line[3:].strip()
        if loc:
            return (loc, ip)
    except Exception:
        pass
    finally:
        if proc:
            proc.terminate()
            try: proc.wait(timeout=2)
            except: proc.kill()
        if tmp_cfg and os.path.exists(tmp_cfg):
            try: os.unlink(tmp_cfg)
            except: pass
    return None

def main():
    os.makedirs(OUTDIR, exist_ok=True)
    need("curl", "curl")
    engine, bin_path = get_proxy_bin()
    print(f"[*] 使用引擎: {engine} ({bin_path})")
    # clash 需要额外安装
    if engine == "clash":
        sh("curl -L -o /usr/local/bin/clash https://github.com/Dreamacro/clash/releases/latest/download/clash-linux-amd64.gz 2>/dev/null || true", timeout=300)
    ports = discover_ports()
    print(f"[*] 待试端口 {len(ports)} 个")
    hits = []
    with cf.ThreadPoolExecutor(15) as ex:  # clash 吃内存，降到 15
        futs = {ex.submit(handshake, p, 10, engine, bin_path): p for p in ports}
        for fu in cf.as_completed(futs):
            p = futs[fu]
            if res := fu.result():
                hits.append((p, res<i class="markdown-ref custom">0</i>, res<i class="markdown-ref custom">1</i>))
                print(f"  OK {p} loc={res<i class="markdown-ref custom">0</i>}")
    if not hits:
        print("[x] 零命中"); return
    userinfo = base64.b64encode(f"{METHOD}:{PASSWORD}".encode()).decode().rstrip("=")
    lines = ["port: 7890", "socks-port: 7891", "allow-lan: true",
             "mode: rule", "log-level: info", "external-controller: 127.0.0.1:9090",
             "", "proxy-providers:"]
    for port, loc, _ in sorted(hits):
        tag = f"{loc}-{port}"
        lines += [f"  {tag}:",
                  f"    type: ss",
                  f"    server: {TARGET}",
                  f"    port: {port}",
                  f"    cipher: {METHOD}",
                  f"    password: {PASSWORD}",
                  "    obfs: none", "    udp: true", ""]
    lines += ["rules:", "  - MATCH,DIRECT"]
    with open(os.path.join(OUTDIR, "guangying.yml"), "w") as f:
        f.write("\n".join(lines))
    print(f"[+] guangying.yml 已生成，共 {len(hits)} 个节点")

if __name__ == "__main__":
    main()
