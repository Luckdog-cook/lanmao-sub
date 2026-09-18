#!/usr/bin/env python3
"""影貓 (八爪魚) VPN 節點提取與訂閱生成（優化穩定版）"""
import base64
import binascii
import datetime
import random
import string
import pyaes
import requests
import urllib3

# 停用無效 SSL 證書警告
urllib3.disable_warnings()

# AES 金鑰與向量定義
KEY1_BYTES = b'M8T74hb17KR183b6'
IV1_BYTES = b'242itTn000C480h1'
KEY2_BYTES = b'rwb6c4e7fz$6el%0'
IV2_BYTES = b'z1b6c3t4e5f6k7w8'

def uuid_a():
    """生成 8 位隨機設備識別碼"""
    characters = string.ascii_lowercase + string.digits
    return ''.join(random.choice(characters) for _ in range(8))

def aes_encrypt(key, iv, plaintext):
    """AES-CBC 加密"""
    encrypter = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(key, iv))
    ciphertext = encrypter.feed(plaintext)
    ciphertext += encrypter.feed()
    return binascii.hexlify(ciphertext).decode().upper()

def main():
    session = requests.Session()
    session.trust_env = False
    session.verify = False

    headers = {
        'User-Agent': 'Octopus_Android',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip'
    }

    try:
        # 1. 帳號註冊
        uuid = uuid_a()
        url = 'https://api.ymvpnpro.cc:8700/netbarcloud/vpn/appRegister2?'
        payload_str = (
            '{"password":"123456","checkPassword":"123456",'
            '"invitationCode":"3229","clientIp":"192.168.2.27",'
            f'"from":"5","androidDevice":"{uuid}"}}'
        )
        data = aes_encrypt(KEY1_BYTES, IV1_BYTES, payload_str)
        
        response = session.post(url, headers=headers, params={'data': data}, timeout=15)
        response.raise_for_status()
        phone_number = response.json().get("data", {}).get("phoneNumber")

        if not phone_number:
            print(f"註冊失敗，未取得手機號: {response.text}")
            return

        print(f"註冊成功，手機號: {phone_number}")

        # 2. 帳號登入
        url = 'https://api.ymvpnpro.cc:8700/netbarcloud/vpn/phLogin.do'
        params = {
            'phoneNumber': aes_encrypt(KEY2_BYTES, IV2_BYTES, phone_number),
            'password': '255A42F2A6863798DBB392033F9D2FD7',
            'osType': 'android'
        }
        response = session.post(url, headers=headers, params=params, timeout=15)
        res_data = response.json().get("data", {})
        ph_token = res_data.get("phToken")
        token = res_data.get("vpnToken")

        # 3. 獲取機場訂閱 URL
        url = 'https://api.ymvpnpro.cc:8700/netbarcloud/vpn/airportNode.do'
        params = {'phToken': ph_token, 'phoneNumber': phone_number}
        sub_headers = {
            'User-Agent': 'Octopus_Android',
            'token': token,
            'Connection': 'Keep-Alive'
        }
        proxy_url = session.post(url, headers=sub_headers, params=params, timeout=15).json().get("data")

        if not proxy_url:
            print("無法獲取訂閱 URL")
            return

        print(f"取得訂閱 URL: {proxy_url}")

        # 4. 下載訂閱內容並寫入本地檔案 (供 GitHub Actions 提交)
        clash_headers = {'User-Agent': 'ClashforWindows/0.19.23'}
        sub_res = session.get(proxy_url, headers=clash_headers, timeout=15)
        sub_content = sub_res.text.strip()

        if not sub_content:
            print("獲取到的訂閱內容為空，跳過寫入。")
            return

        # 保存明文訂閱內容
        with open('nodes.txt', 'w', encoding='utf-8') as f:
            f.write(sub_content + '\n')

        # 自動生成 Base64 加密訂閱檔 (適用於通用客戶端)
        base64_sub = base64.b64encode(sub_content.encode('utf-8')).decode('utf-8')
        with open('subscribe.txt', 'w', encoding='utf-8') as f:
            f.write(base64_sub + '\n')

        # 5. 印出流量與過期時間資訊
        subscription_userinfo = sub_res.headers.get('subscription-userinfo')
        if subscription_userinfo:
            info_dict = {}
            for item in subscription_userinfo.split(';'):
                if '=' in item:
                    k, v = item.strip().split('=')
                    info_dict[k] = int(v)

            total_gb = info_dict.get('total', 0) / (1024 ** 3)
            used_gb = (info_dict.get('upload', 0) + info_dict.get('download', 0)) / (1024 ** 3)
            remain_gb = total_gb - used_gb
            expire_time = datetime.datetime.fromtimestamp(info_dict.get('expire', 0))

            print("\n--- 帳號流量資訊 ---")
            print(f"總流量: {total_gb:.2f} GB | 剩餘: {remain_gb:.2f} GB")
            print(f"過期時間: {expire_time.strftime('%Y-%m-%d %H:%M:%S')}")

        print("\n已成功更新並保存: nodes.txt, subscribe.txt")

    except Exception as e:
        print(f"執行過程中發生異常: {e}")
        exit(1) # 讓 Actions 能正確判定失敗

if __name__ == '__main__':
    main()
