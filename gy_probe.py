import base64, json, uuid
import requests
from Crypto.Cipher import AES
BASE="https://www.gynew.men/api/"; KEY=b"Gz#8kP@mQ2xL!nRv4Yw&TbE6sJdF0cAh"; IV=b"Xk3N7pQ1mZ9wL5rT"
H={"agentX":"super-ok-http","User-Agent":"okhttp/4.9.0"}
def dec(s):
    try:
        pt=AES.new(KEY,AES.MODE_CBC,IV).decrypt(base64.b64decode(s.strip()))
        return pt[:-pt[-1]].decode("utf-8","replace")
    except Exception: return None
def call(ep,d):
    try:
        r=requests.post(BASE+ep,data=d,headers=H,timeout=15)
        return dec(r.text) or r.text
    except Exception as e: return f"ERR {e}"
dev="di:"+uuid.uuid4().hex[:16]
p={"imei":dev,"user":"0","v":"3.2.1","cid":"1","a":"13","b":"google","c":"Pixel 7","d":"redfin"}
info=call("user/getInfo",p); print("[getInfo]",info[:200])
try: uid=json.loads(info)["user"]
except Exception: uid="0"
print("uid=",uid)
p["user"]=uid
for ep in ["user/getlist","user/getserver","user/getInfo"]:
    o=call(ep,p)
    print(f"[{ep} user={uid}]",(o or "")[:400])
