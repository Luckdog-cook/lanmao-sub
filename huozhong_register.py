#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
火种VPN 自动注册脚本（邀请码已改为 nyn5yaq）
注意：需要安装 tesseract 才能 OCR 验证码
"""

import requests
import base64
import random
import string
import os
import sys

try:
    from PIL import Image
    from io import BytesIO
    import pytesseract
except ImportError:
    print("请先安装: pip install pillow pytesseract")
    print("系统还需安装 tesseract-ocr")
    sys.exit(1)

GENERATE_URL = 'https://server6.huozhong.xyz/captcha/generate'
VALIDATE_URL = 'https://server6.huozhong.xyz/captcha/validate'
REGISTER_URL = 'https://server6.huozhong.xyz/users'

HEADERS = {
    'User-Agent': 'ktor-client',
    'Accept': 'application/json',
    'Accept-Encoding': 'gzip',
    'accept-charset': 'UTF-8',
    'Content-Type': 'application/json'
}

USERNAME_LEN = 10
PASSWORD_LEN = 10
DEVICEID_LEN = 16
RETRY_TIMES = 3
CHAR_SET = string.ascii_lowercase + string.digits
REFERRAL_CODE = "nyn5yaq"   # 已改成你的邀请码

def random_str(length):
    return ''.join(random.choice(CHAR_SET) for _ in range(length))

def gen_random_info():
    username = random_str(USERNAME_LEN)
    password = random_str(PASSWORD_LEN)
    device_id = random_str(DEVICEID_LEN)
    return {
        "username": username,
        "password": password,
        "firstName": None,
        "lastName": None,
        "email": None,
        "appliedReferralCode": REFERRAL_CODE,
        "deviceId": device_id
    }

def get_captcha():
    resp = requests.get(GENERATE_URL, headers=HEADERS, timeout=15)
    resp.raise_for_status()
    data = resp.json()
    return data['captchaId'], data['imageBase64'], resp.cookies

def ocr_captcha(image_base64):
    image_data = base64.b64decode(image_base64)
    image = Image.open(BytesIO(image_data))
    image = image.convert('L')
    image = image.point(lambda x: 255 if x > 127 else 0, '1')
    code = pytesseract.image_to_string(
        image,
        config='--psm 8 -l eng -c tessedit_char_whitelist=0123456789'
    ).strip()
    return code if code else None

def validate_captcha(captcha_id, user_input, cookies):
    data = {"captchaId": captcha_id, "userInput": user_input}
    resp = requests.post(VALIDATE_URL, headers=HEADERS, json=data, cookies=cookies, timeout=15)
    resp.raise_for_status()
    result = resp.json()
    return result, result.get('token'), resp.cookies

def user_register(captcha_token, cookies, register_data):
    register_url = f"{REGISTER_URL}?captchaToken={captcha_token}"
    resp = requests.post(register_url, headers=HEADERS, json=register_data, cookies=cookies, timeout=15)
    resp.raise_for_status()
    return resp.json()

def single_register_with_retry(reg_info):
    for retry in range(1, RETRY_TIMES + 1):
        print(f"🔍 验证码获取/验证 [第{retry}/{RETRY_TIMES}次尝试]")
        try:
            captcha_id, image_b64, cookies = get_captcha()
            code = ocr_captcha(image_b64)
            if not code:
                raise Exception("OCR识别为空，未提取到数字")
            print(f"📝 验证码识别结果: {code}")
            validate_result, captcha_token, validate_cookies = validate_captcha(captcha_id, code, cookies)
            if not validate_result.get('valid'):
                raise Exception(f"验证失败: {validate_result.get('message', '验证不通过')}")
            print(f"✅ 验证码验证成功，开始注册...")
            reg_result = user_register(captcha_token, validate_cookies, reg_info)
            return reg_result
        except Exception as e:
            if retry == RETRY_TIMES:
                raise Exception(f"验证码重试{RETRY_TIMES}次均失败: {str(e)}")
            else:
                print(f"❌ 本次失败: {str(e)}，准备重试...\n")
                continue
    raise Exception("未知错误，注册终止")

if __name__ == '__main__':
    print("===== 火种账号自动注册脚本 =====")
    print(f"邀请码已固定为: {REFERRAL_CODE}")

    # 支持环境变量指定注册数量，默认 1
    loop_times = int(os.getenv("REGISTER_COUNT", "1"))
    print(f"将注册 {loop_times} 个账号\n")

    success_count = 0
    fail_count = 0
    fail_list = []
    success_accounts = []

    for i in range(1, loop_times + 1):
        print(f"========== 处理第{i}/{loop_times}个账号 ==========")
        reg_info = gen_random_info()
        print(f"🎲 用户名：{reg_info['username']}  密码：{reg_info['password']}")
        try:
            reg_result = single_register_with_retry(reg_info)
            success_count += 1
            success_accounts.append({
                "username": reg_info["username"],
                "password": reg_info["password"],
                "userId": reg_result.get("userId")
            })
            print(f"🎉 注册成功！用户ID: {reg_result.get('userId')}")
        except Exception as e:
            fail_count += 1
            fail_list.append(f"{reg_info['username']} - {str(e)}")
            print(f"❌ 注册失败：{str(e)}")
        print("=" * 50 + "\n")

    print("===== 注册完成 =====")
    print(f"成功：{success_count}  失败：{fail_count}")
    if success_accounts:
        print("\n成功账号列表：")
        for acc in success_accounts:
            print(f"  用户名: {acc['username']}  密码: {acc['password']}  ID: {acc['userId']}")
    if fail_list:
        print("\n失败详情：")
        for f in fail_list:
            print(f"  - {f}")
