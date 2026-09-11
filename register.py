#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
火种批量注册脚本
邀请码默认：nyn5yaq
"""

import os
import json
import argparse
import requests
import base64
import random
import string
from PIL import Image
from io import BytesIO
import pytesseract
from datetime import datetime

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

DEFAULT_USERNAME_LEN = 10
DEFAULT_PASSWORD_LEN = 10
DEFAULT_DEVICEID_LEN = 16
DEFAULT_RETRY_TIMES = 3
CHAR_SET = string.ascii_lowercase + string.digits
DEFAULT_REFERRAL_CODE = "nyn5yaq"


def load_referral_code() -> str:
    code = os.getenv('REFERRAL_CODE', '').strip()
    if code:
        print(f"✅ 使用环境变量邀请码: {code}")
        return code

    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                code = str(data.get('referral_code', '')).strip()
                if code:
                    print(f"✅ 使用 config.json 邀请码: {code}")
                    return code
        except Exception as e:
            print(f"⚠️ 读取 config.json 失败: {e}")

    print(f"✅ 使用默认邀请码: {DEFAULT_REFERRAL_CODE}")
    return DEFAULT_REFERRAL_CODE


def random_str(length: int) -> str:
    return ''.join(random.choice(CHAR_SET) for _ in range(length))


def gen_random_info(referral_code: str) -> dict:
    return {
        "username": random_str(DEFAULT_USERNAME_LEN),
        "password": random_str(DEFAULT_PASSWORD_LEN),
        "firstName": None,
        "lastName": None,
        "email": None,
        "appliedReferralCode": referral_code,
        "deviceId": random_str(DEFAULT_DEVICEID_LEN)
    }


def get_captcha():
    resp = requests.get(GENERATE_URL, headers=HEADERS, timeout=15)
    resp.raise_for_status()
    data = resp.json()
    return data['captchaId'], data['imageBase64'], resp.cookies


def ocr_captcha(image_base64: str):
    image_data = base64.b64decode(image_base64)
    image = Image.open(BytesIO(image_data))
    image = image.convert('L')
    image = image.point(lambda x: 255 if x > 127 else 0, '1')
    code = pytesseract.image_to_string(
        image,
        config='--psm 8 -l eng -c tessedit_char_whitelist=0123456789'
    ).strip()
    return code if code else None


def validate_captcha(captcha_id: str, user_input: str, cookies):
    data = {"captchaId": captcha_id, "userInput": user_input}
    resp = requests.post(VALIDATE_URL, headers=HEADERS, json=data, cookies=cookies, timeout=15)
    resp.raise_for_status()
    result = resp.json()
    return result, result.get('token'), resp.cookies


def user_register(captcha_token: str, cookies, register_data: dict):
    url = f"{REGISTER_URL}?captchaToken={captcha_token}"
    resp = requests.post(url, headers=HEADERS, json=register_data, cookies=cookies, timeout=20)
    resp.raise_for_status()
    return resp.json()


def single_register_with_retry(reg_info: dict, retry_times: int):
    for retry in range(1, retry_times + 1):
        print(f"🔍 验证码 [第{retry}/{retry_times}次]")
        try:
            captcha_id, image_b64, cookies = get_captcha()
            code = ocr_captcha(image_b64)
            if not code:
                raise Exception("OCR识别为空")
            print(f"📝 识别结果: {code}")

            validate_result, captcha_token, validate_cookies = validate_captcha(captcha_id, code, cookies)
            if not validate_result.get('valid'):
                raise Exception(f"验证失败: {validate_result.get('message', '不通过')}")

            print("✅ 验证成功，开始注册...")
            return user_register(captcha_token, validate_cookies, reg_info)
        except Exception as e:
            if retry == retry_times:
                raise Exception(f"重试{retry_times}次均失败: {e}")
            print(f"❌ 失败: {e}，准备重试...\n")
    raise Exception("未知错误")


def save_account(info: dict, user_id: str, filepath: str = "accounts.txt"):
    line = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {info['username']} | {info['password']} | {info['deviceId']} | {user_id}\n"
    with open(filepath, "a", encoding="utf-8") as f:
        f.write(line)
    print(f"💾 已保存到 {filepath}")


def main():
    parser = argparse.ArgumentParser(description="火种批量注册")
    parser.add_argument("-n", "--num", type=int, default=1, help="注册数量")
    parser.add_argument("-r", "--retry", type=int, default=DEFAULT_RETRY_TIMES, help="重试次数")
    parser.add_argument("--no-save", action="store_true", help="不保存账号")
    args = parser.parse_args()

    print("=" * 50)
    print("===== 火种批量注册 =====")
    print("=" * 50)

    referral = load_referral_code()
    print(f"📌 当前邀请码: {referral}\n")

    success, fail = 0, 0
    fail_list = []

    for i in range(1, args.num + 1):
        print(f"========== 第 {i}/{args.num} 个 ==========")
        reg_info = gen_random_info(referral)
        print(f"用户名: {reg_info['username']}")
        print(f"密码  : {reg_info['password']}")

        try:
            result = single_register_with_retry(reg_info, args.retry)
            success += 1
            user_id = result.get("userId", "N/A")
            print(f"🎉 成功！用户ID: {user_id}")
            if not args.no_save:
                save_account(reg_info, user_id)
        except Exception as e:
            fail += 1
            fail_list.append(f"第{i}个: {e}")
            print(f"❌ 失败: {e}")
        print("=" * 50 + "\n")

    print(f"📊 总计: {args.num} | 成功: {success} | 失败: {fail}")
    if fail_list:
        for item in fail_list:
            print(f"  - {item}")


if __name__ == "__main__":
    main()
