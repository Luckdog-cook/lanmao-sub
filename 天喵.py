#!/usr/bin/env python3
"""天貓 （優化穩定版）"""
import base64
import json
import random
import time
import urllib.parse
import uuid
import requests
import urllib3

urllib3.disable_warnings()

API = 'https://api.tianmiao.icu/api'
INVITE = 'ghqhsqRD'
UA = ['okhttp/4.12.0', 'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36']

s = requests.Session()
s.verify = False

def hdr(tok=None, auth=None):
    h = {
        'deviceid': str(uuid.uuid4()),
        'devicetype': '1',
        'Content-Type': 'application/json; charset=UTF-8',
        'User-Agent': random.choice(UA)
    }
    if tok and auth:
        h['token'] = tok
        h['authtoken'] = auth
    return h

def main():
    try:
        # 1. 註冊
        r = s.post(f'{API}/register', headers=hdr(), json={
            'email': f't{int(time.time())}@qq.com',
            'password': 'asd789369',
            'password_word': 'asd789369'
        }, timeout=15)
        r.raise_for_status()
        d = r.json()
        
        if d.get('code') != 0 and 'data' not in d:
            print(f"註冊失敗: {d}")
            return

        tok, auth = d['data']['auth_data'], d['data']['token']
        print(f'註冊成功: {tok[:20]}...')

        time.sleep(1)

        # 2. 綁定邀請碼
        r = s.post(f'{API}/bandInviteCode', headers=hdr(tok, auth), json={'invite_code': INVITE}, timeout=15)
        print('邀請碼響應:', r.json().get('message', '無回應'))

        time.sleep(1)

        # 3. 獲取節點
        r = s.post(f'{API}/nodeListV2', headers=hdr(tok, auth), json={
            'protocol': 'all',
            'include_ss': '1',
            'include_shadowsocks': '1',
            'include_trojan': '1'
        }, timeout=15)
        
        nodes_data = r.json().get('data', [])
        vip = []
        for g in nodes_data:
            if g.get('type') == 'vip':
                for n in g.get('node', []):
                    if isinstance(n, dict) and 'url' in n:
                        vip.append(n)

        print(f'成功抓取 VIP 節點: {len(vip)} 個')

        if not vip:
            print("未獲取到任何節點，跳過寫入。")
            return

        urls = [n['url'] for n in vip]

        # 4. 保存原始鏈接
        with open('nodes.txt', 'w', encoding='utf-8') as f:
            f.write('\n'.join(urls) + '\n')

        # 5. Base64 訂閱
        sub = base64.b64encode('\n'.join(urls).encode('utf-8')).decode('utf-8')
        with open('subscribe.txt', 'w', encoding='utf-8') as f:
            f.write(sub)

        # 6. 解析為結構化 JSON（vless only）
        proxies = []
        for u in urls:
            if not u.startswith('vless://'):
                continue
            parsed = urllib.parse.urlparse(u)
            name = urllib.parse.unquote(parsed.fragment)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            proxies.append({
                'name': name,
                'type': 'vless',
                'server': parsed.hostname,
                'port': parsed.port,
                'uuid': parsed.username,
                'security': params.get('security', 'none'),
                'sni': params.get('sni', parsed.hostname),
                'pbk': params.get('pbk', ''),
                'sid': params.get('sid', ''),
                'flow': params.get('flow', ''),
                'network': params.get('type', 'tcp')
            })

        with open('nodes.json', 'w', encoding='utf-8') as f:
            json.dump({'count': len(proxies), 'proxies': proxies}, f, ensure_ascii=False, indent=2)

        print('已成功更新並保存: nodes.txt, subscribe.txt, nodes.json')

    except Exception as e:
        print(f"運行過程發生異常: {e}")
        exit(1) # 讓 Actions 能捕捉到錯誤狀態

if __name__ == '__main__':
    main()
