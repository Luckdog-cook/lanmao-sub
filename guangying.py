#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""光影VPN 节点猎手 v6.4 -- GitHub Actions 版（自动下载 sslocal 静态二进制，支持本地 clash）"""

import base64, concurrent.futures as cf, os, random, re, shutil, subprocess, sys, time, tempfile

TARGET   = "43.159.7.5"
METHOD   = "aes-128-gcm"
PASSWORD = "2wsxcde3"
KNOWN    = [21574, 31597, 35933, 36735, 40322, 49277, 53907]
TRACE    = "https://www.cloudflare.com/cdn-cgi/trace"
OUTDIR   = os.path.dirname(os.path.abspath(__file__))

def sh(cmd, timeout=300):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)

def get_proxy_bin():
    for b in ("ss-local", "sslocal"):
        if shutil.which(b):
            return ("ss", b)
    if shutil.which("clash"):
        return ("clash", "clash")
    sys.exit("[x] 无 ss 客户端也无 clash，请先运行 workflow 的 Download 步骤")

def discover_ports():
    if os.environ.get("GITHUB_ACTIONS") == "true":
        return sorted(set(KNOWN + [36736, 49278, 53908]))
    if shutil.which("masscan"):
        ports = set()
        sh(f"masscan -p1-65535 {TARGET} --rate 300 -oL /tmp/m1", timeout=600)
        for line in open("/tmp/m1", errors="ignore"):
            m = re.match(r"open tcp (\d+)", line)
            if m: ports.add(int(m.group(1)))
        return sorted(ports)
    return sorted(KNOWN)

def make_clash_config(port, lp):
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

def handshake(port, timeout=9, engine=None, bin_path=None):
    lp = random.randint(20000, 59999)
    proc, tmp_cfg, curl_cmd, cmd = None, None, None, None
    try:
        if engine == "clash":
            fd, tmp_cfg = tempfile.mkstemp(suffix=".yml")
            with os.fdopen(fd, "w") as f:
                f.write(make_clash_config(port, lp))
            cmd = [bin_path, "-f", tmp_cfg]
            curl_cmd = ["curl", "-s", "-x", f"http://127.0.0.1:{lp}", "-m", str(timeout), TRACE]
            wait = 1.2
        else:
            cmd = [bin_path, "-s", TARGET, "-p", str(port), "-l", str(lp),
                   "-m", METHOD, "-k", PASSWORD, "-t", "5"]
            curl_cmd = ["curl", "-s", "--socks5-hostname", f"127.0.0.1:{lp}",
                        "-m", str(timeout), TRACE]
            wait = 0.6
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(wait)
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
    engine, bin_path = get_proxy_bin()
    print(f"[*] 引擎: {engine} ({bin_path})")
    ports = discover_ports()
    print(f"[*] 待试端口 {len(ports)} 个")
    hits = []
    workers = 15 if engine == "clash" else 25
    with cf.ThreadPoolExecutor(workers) as ex:
        futs = {ex.submit(handshake, p, 9, engine, bin_path): p for p in ports}
        for fu in cf.as_completed(futs):
            p = futs[fu]
            if res := fu.result():
                hits.append((p, res<i class="markdown-ref custom">0</i>, res<i class="markdown-ref custom">1</i>))
                print(f"  OK {p} loc={res<i class="markdown-ref custom">0</i>}")
    if not hits:
        print("[x] 零命中，保留旧 guangying.yml 不覆盖")
        return
    lines = ["port: 7890", "socks-port: 7891", "allow-lan: true",
             "mode: rule", "log-level: info", "external-controller: 127.0.0.1:9090",
             "", "proxy-providers:"]
    for port, loc, _ in sorted(hits):
        tag = f"{loc}-{port}"
        lines += [f"  {tag}:", f"    type: ss", f"    server: {TARGET}",
                  f"    port: {port}", f"    cipher: {METHOD}",
                  f"    password: {PASSWORD}", "    obfs: none", "    udp: true", ""]
    lines += ["rules:", "  - MATCH,DIRECT"]
    with open(os.path.join(OUTDIR, "guangying.yml"), "w") as f:
        f.write("\n".join(lines))
    print(f"[+] guangying.yml 已生成，共 {len(hits)} 个节点")

if __name__ == "__main__":
    main()
