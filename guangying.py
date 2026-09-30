#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""光影VPN 节点猎手 v6.5 -- GitHub Actions 版（ss-rust 静态二进制 + 本地 clash 引擎支持）"""

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
    sys.exit("no ss or clash found")

def discover_ports():
    if os.environ.get("GITHUB_ACTIONS") == "true":
        return sorted(set(KNOWN + [36736, 49278, 53908]))
    if shutil.which("masscan"):
        ports = set()
        sh("masscan -p1-65535 %s --rate 300 -oL /tmp/m1" % TARGET, timeout=600)
        for line in open("/tmp/m1", errors="ignore"):
            m = re.match(r"open tcp (\d+)", line)
            if m:
                ports.add(int(m.group(1)))
        return sorted(ports)
    return sorted(KNOWN)

def make_clash_config(port, lp):
    return "mixed-port: %d\n" \
           "allow-lan: false\n" \
           "mode: global\n" \
           "log-level: silent\n" \
           "proxies:\n" \
           "  - name: probe\n" \
           "    type: ss\n" \
           "    server: %s\n" \
           "    port: %d\n" \
           "    cipher: %s\n" \
           "    password: %s\n" \
           "    udp: true\n" \
           "proxy-groups:\n" \
           "  - name: PROXY\n" \
           "    type: select\n" \
           "    proxies: [probe]\n" \
           "rules:\n" \
           "  - MATCH,PROXY\n" % (lp, TARGET, port, METHOD, PASSWORD)

def handshake(port, timeout=9, engine=None, bin_path=None):
    lp = random.randint(20000, 59999)
    proc = None
    tmp_cfg = None
    curl_cmd = None
    cmd = None
    wait = 0.6
    try:
        if engine == "clash":
            fd, tmp_cfg = tempfile.mkstemp(suffix=".yml")
            with os.fdopen(fd, "w") as f:
                f.write(make_clash_config(port, lp))
            cmd = [bin_path, "-f", tmp_cfg]
            curl_cmd = ["curl", "-s", "-x", "http://127.0.0.1:%d" % lp, "-m", str(timeout), TRACE]
            wait = 1.2
        else:
            cmd = [bin_path, "-s", TARGET, "-p", str(port), "-l", str(lp),
                   "-m", METHOD, "-k", PASSWORD, "-t", "5"]
            curl_cmd = ["curl", "-s", "--socks5-hostname", "127.0.0.1:%d" % lp,
                        "-m", str(timeout), TRACE]
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(wait)
        r = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=timeout + 3)
        loc = None
        ip = None
        for line in r.stdout.splitlines():
            if line.startswith("loc="):
                loc = line[4:].strip()
            if line.startswith("ip="):
                ip = line[3:].strip()
        if loc:
            return (loc, ip)
    except Exception:
        pass
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except Exception:
                proc.kill()
        if tmp_cfg and os.path.exists(tmp_cfg):
            try:
                os.unlink(tmp_cfg)
            except Exception:
                pass
    return None

def main():
    os.makedirs(OUTDIR, exist_ok=True)
    engine, bin_path = get_proxy_bin()
    print("[*] engine: %s (%s)" % (engine, bin_path))
    ports = discover_ports()
    print("[*] ports to test: %d" % len(ports))
    hits = []
    workers = 15 if engine == "clash" else 25
    with cf.ThreadPoolExecutor(workers) as ex:
        futs = {ex.submit(handshake, p, 9, engine, bin_path): p for p in ports}
        for fu in cf.as_completed(futs):
            p = futs[fu]
            res = fu.result()
            if res is not None:
                _loc = res<i class="markdown-ref custom">0</i>
                _ip = res<i class="markdown-ref custom">1</i>
                hits.append((p, _loc, _ip))
                print("  OK %d loc=%s" % (p, _loc))
    if not hits:
        print("[x] no hits, keep old guangying.yml")
        return
    lines = ["port: 7890", "socks-port: 7891", "allow-lan: true",
             "mode: rule", "log-level: info", "external-controller: 127.0.0.1:9090",
             "", "proxy-providers:"]
    for port, loc, _ in sorted(hits):
        tag = "%s-%d" % (loc, port)
        lines.append("  %s:" % tag)
        lines.append("    type: ss")
        lines.append("    server: %s" % TARGET)
        lines.append("    port: %d" % port)
        lines.append("    cipher: %s" % METHOD)
        lines.append("    password: %s" % PASSWORD)
        lines.append("    obfs: none")
        lines.append("    udp: true")
        lines.append("")
    lines.append("rules:")
    lines.append("  - MATCH,DIRECT")
    with open(os.path.join(OUTDIR, "guangying.yml"), "w") as f:
        f.write("\n".join(lines))
    print("[+] guangying.yml generated, %d nodes" % len(hits))

if __name__ == "__main__":
    main()
