import base64, json, os, subprocess, sys, tempfile, time
import urllib.request

SUB = os.environ.get("JD_SUB", "jidian_sub.txt")

def load():
    lines = [l.strip() for l in open(SUB) if l.strip()]
    return lines

def parse(uri):
    if uri.startswith("ss://"):
        body = uri[5:].split("#")[0]
        if "@" in body:
            head, tail = body.split("@", 1)
            dec = base64.b64decode(head + "===").decode()
            method, pwd = dec.split(":", 1)
            host, port = tail.split(":", 1)
            return {"type": "shadowsocks", "method": method, "password": pwd,
                    "server": host, "server_port": int(port)}
    if uri.startswith("anytls://"):
        from urllib.parse import urlparse, parse_qs
        u = urlparse(uri)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        return {"type": "anytls", "password": u.username, "server": u.hostname,
                "server_port": u.port, "tls": {"enabled": True,
                "server_name": q.get("sni", ""), "insecure": True}}
    return None

def test(i, uri):
    ob = parse(uri)
    if not ob:
        return (uri[-30:], "SKIP", "")
    conf = {"log": {"level": "error"},
            "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": 11600 + i}],
            "outbounds": [ob]}
    fd, path = tempfile.mkstemp(suffix=".json")
    os.write(fd, json.dumps(conf).encode()); os.close(fd)
    p = subprocess.Popen(["./sing-box", "run", "-c", path],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.2)
    t0 = time.time()
    try:
        r = subprocess.run(["curl", "-s", "-m", "8", "--socks5-hostname",
                            f"127.0.0.1:{11600 + i}",
                            "http://ip-api.com/json/?fields=status,country,city,query"],
                           capture_output=True, text=True, timeout=10)
        d = json.loads(r.stdout) if r.stdout.strip().startswith("{") else {}
        res = f'{d.get("query")} {d.get("country")}/{d.get("city")}' if d.get("status") == "success" else "FAIL"
    except Exception:
        res = "FAIL"
    ms = int((time.time() - t0) * 1000)
    p.terminate()
    try:
        p.wait(2)
    except Exception:
        p.kill()
    os.unlink(path)
    from urllib.parse import unquote
    return (unquote(uri.split("#")[-1]), res, f"{ms}ms")

if __name__ == "__main__":
    lines = load()
    print(f"共 {len(lines)} 个节点")
    ok = 0
    for i, u in enumerate(lines):
        name, res, ms = test(i, u)
        if res not in ("FAIL", "SKIP"):
            ok += 1
        print(f"  {name:<14} {res:<28} {ms}")
    print(f"可用 {ok}/{len(lines)}")
