#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""光影VPN 节点猎手 v6.8 -- GitHub Actions 版，适配 sslocal 新版 --server-url"""

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
    sys.exit("no sslocal engine found")

def discover_ports():
    if os.environ.get("GITHUB_ACTIONS") == "true":
        return sorted(set(KNOWN + [36736, 49278, 53908]))
    return sorted(KNOWN)

def handshake(port, timeout=9, bin_path=None):
    lp = random.randint(20000, 59999)
    proc = None
    # 新版 sslocal(s) 用 --server-url 传整条 ss:// 链接
    # 形式: ss://base64(method:password)@host:port
    userinfo = base64.b64encode(("%s:%s" % (METHOD, PASSWORD)).encode()).decode()
    server_url = "ss://%s@%s:%d" % (userinfo, TARGET, port)
    cmd = [bin_path, "-b", "127.0.0.1:%d" % lp, "--server-url", server_url]
    curl_cmd = ["curl", "-s", "--socks5-hostname", "127.0.0.1:%d" % lp,
                "-m", str(timeout), TRACE]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.0)  # 新版 sslocal 启动稍慢
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
    return None

def main():
    os.makedirs(OUTDIR, exist_ok=True)
    _engine, bin_path = get_proxy_bin()
    print("[*] engine: sslocal (%s)" % bin_path)
    ports = discover_ports()
    print("[*] ports to test: %d" % len(ports))
    hits = []
    with cf.ThreadPoolExecutor(20) as ex:
        futs = {ex.submit(handshake, p, 10, bin_path): p for p in ports}
        for fu in cf.as_completed(futs):
            p = futs[fu]
            res = fu.result()
            if res is not None:
                loc, ip = res
                hits.append((p, loc, ip))
                print("  OK %d loc=%s" % (p, loc))
    if not hits:
        print("[x] no hits, keep old guangying.txt")
        return
    # 输出 clash 订阅格式: 每行一个 ss:// 节点
    sub_lines = []
    for p in sorted(_p for _p, _loc, _ip in hits):
        userinfo = base64.b64encode(("%s:%s" % (METHOD, PASSWORD)).encode()).decode()
        sub_lines.append("ss://%s@%s:%d" % (userinfo, TARGET, p))
    with open(os.path.join(OUTDIR, "guangying.txt"), "w") as f:
        f.write("\n".join(sub_lines) + "\n")
    print("[+] guangying.txt generated, %d nodes" % len(hits))

if __name__ == "__main__":
    main()
