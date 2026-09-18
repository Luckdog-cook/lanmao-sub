"""滑翔伞 VPN 接口客户端（仅用于已获授权的账户和服务）。

依赖：python -m pip install cryptography
运行：
  python 滑翔伞.py register          # 注册账户
  python 滑翔伞.py fetch             # 拉取全部 VIP 节点
  python 滑翔伞.py                   # 交互菜单（本地用）
"""

import argparse
import base64
import binascii
import gzip
import hashlib
import json
import secrets
import string
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "滑翔伞.json"
OUTPUT_PATH = ROOT / "滑翔伞.txt"
TABLE_PATH = ROOT / "whitebox_table.b64"  # 外部白盒表，避免源码粘贴截断
REPLACED_AID = "1002"
DEFAULT_BASE_URL = "https://www.qajjzuyz.net:28075"
DEFAULT_CODE = "EJQRDBB"
SIGN_SUFFIX = "EbbubitewJxcPYpn"
NONCE_ALPHABET = string.ascii_letters + string.digits

# 旧版内置表已移除，改用外部文件。
WHITEBOX_TABLE_B64 = None


class WhiteboxAes:
    """纯 Python 实现的 APK 白盒 AES-256 块函数。"""

    TABLE_SIZE = 0xB7000
    ROUND_INPUT = 0x00000
    ROUND_NETWORK = 0x34000
    ROUND_OUTPUT = 0x82000
    FINAL_ROUND = 0xB6000

    @classmethod
    def _load_from_file(cls) -> bytes | None:
        if not TABLE_PATH.is_file():
            return None
        raw = TABLE_PATH.read_text(encoding="utf-8").strip()
        try:
            compressed = base64.b64decode(raw)
            data = gzip.decompress(compressed)
        except Exception:
            return None
        if len(data) == cls.TABLE_SIZE:
            return data
        return None

    @classmethod
    def _load_from_builtin(cls) -> bytes | None:
        if not WHITEBOX_TABLE_B64:
            return None
        try:
            compressed = base64.b64decode(WHITEBOX_TABLE_B64)
            data = gzip.decompress(compressed)
        except Exception:
            return None
        if len(data) == cls.TABLE_SIZE:
            return data
        return None

    def __init__(self) -> None:
        self.tables = self._load_from_file() or self._load_from_builtin()
        if self.tables is None:
            raise RuntimeError(
                "白盒 AES 表缺失或损坏。\n"
                f"请将完整的 base64 白盒表（gzip 压缩后 base64 编码，解压后长度 {self.TABLE_SIZE} 字节）"
                f"保存到：{TABLE_PATH}\n"
                "如果你已有旧版完整脚本，可用下面命令导出：\n"
                "  python -c \"import 滑翔伞; open('whitebox_table.b64','w').write(滑翔伞.WHITEBOX_TABLE_B64.decode())\"\n"
                "然后将 whitebox_table.b64 与 滑翔伞.py 一起提交到仓库。"
            )

    def _u32(self, offset: int) -> int:
        table = self.tables
        return table[offset] | table[offset + 1] << 8 | table[offset + 2] << 16 | table[offset + 3] << 24

    def _t(self, offset: int) -> int:
        return self.tables[self.ROUND_NETWORK + offset]

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("AES block 必须为 16 字节")
        state = list(block)
        t = self._t
        u32 = self._u32
        input_base = self.ROUND_INPUT
        output_base = self.ROUND_OUTPUT

        for round_index in range(13):
            state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
            state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
            state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]

            round_input = round_index * 0x4000
            for column in range(4):
                position = column * 4
                network = column * 0x1800
                column_input = round_input + column * 0x1000
                value_25 = u32(input_base + column_input + state[position] * 4)
                value_26 = u32(input_base + column_input + (state[position + 2] + 512) * 4)
                value_27 = u32(input_base + column_input + (state[position + 1] + 256) * 4)
                value_28 = u32(input_base + column_input + (state[position + 3] + 768) * 4)

                value_29 = t(network + 1536 + ((value_25 >> 16) & 0xF0 | (value_27 >> 20) & 0x0F))
                value_30 = t(
                    network
                    + 1280
                    + 16 * t(network + 512 + ((value_25 >> 20) & 0xF0 | (value_27 >> 24) & 0x0F))
                    + t(network + 768 + ((value_26 >> 20) & 0xF0 | (value_28 >> 24) & 0x0F))
                ) | (
                    16
                    * t(
                        network
                        + 1024
                        + 16 * t(network + ((value_25 >> 24) & 0xF0 | (value_27 >> 28) & 0x0F))
                        + t(network + 256 + ((value_26 >> 24) & 0xF0 | (value_28 >> 28) & 0x0F))
                    )
                )
                value_31 = t(network + 2304 + ((value_26 >> 12) & 0xF0 | (value_28 >> 16) & 0x0F)) + 16 * t(
                    network + 2048 + ((value_25 >> 12) & 0xF0 | (value_27 >> 16) & 0x0F)
                )
                value_32 = t(network + 3328 + ((value_26 >> 8) & 0xF0 | (value_28 >> 12) & 0x0F)) + 16 * t(
                    network + 3072 + ((value_25 >> 8) & 0xF0 | (value_27 >> 12) & 0x0F)
                )
                value_33 = ((value_25 >> 4) & 0xF0) | ((value_27 >> 8) & 0x0F)
                value_34 = (value_25 & 0xF0) | ((value_27 >> 4) & 0x0F)
                value_35 = t(network + 1792 + ((value_26 >> 16) & 0xF0 | (value_28 >> 20) & 0x0F))
                value_36 = (value_27 & 0x0F) | (16 * (value_25 & 0x0F))
                value_37 = (value_26 & 0xF0) | ((value_28 >> 4) & 0x0F)
                value_38 = t(network + 3840 + ((value_26 >> 4) & 0xF0 | (value_28 >> 8) & 0x0F))
                value_39 = (value_28 & 0x0F) | (16 * (value_26 & 0x0F))
                value_31 = t(network + 2816 + value_31) | 16 * t(network + 2560 + 16 * value_29 + value_35)
                value_35 = t(network + 0x1100 + 16 * t(network + 3584 + value_33) + value_38) | 16 * t(
                    network + 4096 + value_32
                )
                value_40 = u32(output_base + column_input + value_30 * 4)
                value_32 = t(network + 0x1700 + 16 * t(network + 0x1400 + value_36) + t(network + 0x1500 + value_39)) | 16 * t(
                    network + 0x1600 + 16 * t(network + 0x1200 + value_34) + t(network + 0x1300 + value_37)
                )
                value_41 = u32(output_base + column_input + (value_31 + 256) * 4)
                value_42 = u32(output_base + column_input + (value_35 + 512) * 4)
                value_44 = u32(output_base + column_input + (value_32 + 768) * 4)

                state[position] = t(
                    network
                    + 1280
                    + 16 * t(network + 512 + ((value_40 >> 20) & 0xF0 | (value_41 >> 24) & 0x0F))
                    + t(network + 768 + ((value_42 >> 20) & 0xF0 | (value_44 >> 24) & 0x0F))
                ) | (
                    16
                    * t(
                        network
                        + 1024
                        + 16 * t(network + ((value_40 >> 24) & 0xF0 | (value_41 >> 28) & 0x0F))
                        + t(network + 256 + ((value_42 >> 24) & 0xF0 | (value_44 >> 28) & 0x0F))
                    )
                )
                state[position + 1] = t(
                    network
                    + 2816
                    + 16 * t(network + 2048 + ((value_40 >> 12) & 0xF0 | (value_41 >> 16) & 0x0F))
                    + t(network + 2304 + ((value_42 >> 12) & 0xF0 | (value_44 >> 16) & 0x0F))
                ) | (
                    16
                    * t(
                        network
                        + 2560
                        + 16 * t(network + 1536 + ((value_40 >> 16) & 0xF0 | (value_41 >> 20) & 0x0F))
                        + t(network + 1792 + ((value_42 >> 16) & 0xF0 | (value_44 >> 20) & 0x0F))
                    )
                )
                state[position + 2] = t(
                    network
                    + 0x1100
                    + 16 * t(network + 3584 + ((value_40 >> 4) & 0xF0 | (value_41 >> 8) & 0x0F))
                    + t(network + 3840 + ((value_42 >> 4) & 0xF0 | (value_44 >> 8) & 0x0F))
                ) | (
                    16
                    * t(
                        network
                        + 4096
                        + 16 * t(network + 3072 + ((value_40 >> 8) & 0xF0 | (value_41 >> 12) & 0x0F))
                        + t(network + 3328 + ((value_42 >> 8) & 0xF0 | (value_44 >> 12) & 0x0F))
                    )
                )
                high = t(
                    network
                    + 0x1600
                    + 16 * t(network + 0x1200 + ((value_40 & 0xF0) | ((value_41 & 0xFF) >> 4)))
                    + t(network + 0x1300 + ((value_42 & 0xF0) | ((value_44 & 0xFF) >> 4)))
                )
                low = t(
                    network
                    + 0x1700
                    + 16 * t(network + 0x1400 + ((value_41 & 0x0F) | (16 * (value_40 & 0x0F))))
                    + t(network + 0x1500 + ((value_44 & 0x0F) | (16 * (value_42 & 0x0F))))
                )
                state[position + 3] = low | 16 * high

        original = state[:]
        final = self.tables
        final_base = self.FINAL_ROUND
        return bytes(
            (
                final[final_base + original[0]],
                final[final_base + 256 + original[5]],
                final[final_base + 512 + original[10]],
                final[final_base + 768 + original[15]],
                final[final_base + 1024 + original[4]],
                final[final_base + 1280 + original[9]],
                final[final_base + 1536 + original[14]],
                final[final_base + 1792 + original[3]],
                final[final_base + 2048 + original[8]],
                final[final_base + 2304 + original[13]],
                final[final_base + 2560 + original[2]],
                final[final_base + 2816 + original[7]],
                final[final_base + 3072 + original[12]],
                final[final_base + 3328 + original[1]],
                final[final_base + 3584 + original[6]],
                final[final_base + 3840 + original[11]],
            )
        )

    def crypt_ctr(self, data: bytes, nonce: str) -> bytes:
        counter = bytearray(nonce.encode("ascii"))
        if len(counter) != 16:
            raise ValueError("nonce 必须为 16 个 ASCII 字符")

        output = bytearray()
        for offset in range(0, len(data), 16):
            keystream = self.encrypt_block(bytes(counter))
            chunk = data[offset : offset + 16]
            output.extend(left ^ right for left, right in zip(chunk, keystream))
            for index in range(15, -1, -1):
                counter[index] = (counter[index] + 1) & 0xFF
                if counter[index]:
                    break
        return bytes(output)


def sign(parameters: dict[str, str]) -> str:
    """客户端算法：按键排序拼接 key+value，追加固定盐，计算 MD5。"""
    canonical = "".join(key + value for key, value in sorted(parameters.items()) if key != "sign")
    return hashlib.md5((canonical + SIGN_SUFFIX).encode("utf-8")).hexdigest()


def decrypt_node_payload(encoded: str) -> dict[str, Any]:
    key = b"ZcgptVicxYRNCPJdUZxRMhqsZuKQgiUZ"
    ciphertext = base64.b64decode(encoded + "=" * (-len(encoded) % 4))
    if not ciphertext or len(ciphertext) % 16:
        raise ValueError("nodedata 密文长度无效")
    decryptor = Cipher(algorithms.AES(key), modes.CBC(key[:16])).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    padding = padded[-1]
    if padding == 0 or padding > 16 or padded[-padding:] != bytes([padding]) * padding:
        raise ValueError("nodedata PKCS#7 填充无效")
    return json.loads(padded[:-padding].decode("utf-8"))


def vmess_link(config: dict[str, Any], label: str) -> str:
    outbound = next((item for item in config.get("outbounds", []) if item.get("protocol") == "vmess"), None)
    if not outbound:
        raise ValueError("节点中未找到 VMess outbound")
    vnext = outbound["settings"]["vnext"][0]
    user = vnext["users"][0]
    stream = outbound.get("streamSettings", {})
    ws_settings = stream.get("wsSettings", {})
    tls_settings = stream.get("tlsSettings", {})
    link_data = {
        "v": "2",
        "ps": label,
        "add": vnext["address"],
        "port": str(vnext["port"]),
        "id": user["id"],
        "aid": REPLACED_AID,
        "scy": user.get("security", "auto"),
        "net": stream.get("network", "tcp"),
        "type": "none",
        "host": ws_settings.get("headers", {}).get("Host", ""),
        "path": ws_settings.get("path", ""),
        "tls": stream.get("security", ""),
        "sni": tls_settings.get("serverName", ""),
    }
    payload = json.dumps(link_data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return "vmess://" + base64.b64encode(payload).decode("ascii")


class ApiClient:
    def __init__(self, settings: dict[str, Any]) -> None:
        self.settings = settings
        self.base_url = str(settings["base_url"]).rstrip("/")
        self.cipher = WhiteboxAes()

    def request(self, path: str, extra: dict[str, str] | None = None, retries: int = 2) -> dict[str, Any]:
        last_exc = None
        for attempt in range(retries + 1):
            try:
                request_parameters = {key: str(value) for key, value in self.settings["parameters"].items()}
                request_parameters["quest_time"] = str(int(time.time() * 1000))
                request_parameters.update({key: str(value) for key, value in (extra or {}).items()})
                request_parameters["sign"] = sign(request_parameters)
                nonce = "".join(secrets.choice(NONCE_ALPHABET) for _ in range(16))
                query = {key: value for key, value in request_parameters.items() if key != "sign"}
                query["n"] = nonce
                body = json.dumps(request_parameters, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                encrypted = self.cipher.crypt_ctr(body, nonce)

                request = Request(
                    f"{self.base_url}{path}?{urlencode(query)}",
                    data=encrypted,
                    headers={"Content-Type": "application/octet-stream"},
                    method="POST",
                )
                with urlopen(request, timeout=30) as response:
                    response_data = response.read()
                plaintext = self.cipher.crypt_ctr(response_data, nonce).decode("utf-8")
                parsed = json.loads(plaintext)
                if not isinstance(parsed, dict):
                    raise RuntimeError("服务响应格式错误")
                return parsed
            except (HTTPError, URLError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                last_exc = exc
                if attempt < retries:
                    time.sleep(1.5 * (attempt + 1))
                    continue
                if isinstance(exc, HTTPError):
                    detail = exc.read().decode("utf-8", errors="replace") if hasattr(exc, "read") else str(exc)
                    raise RuntimeError(f"HTTP {exc.code}: {detail[:300]}") from exc
                if isinstance(exc, URLError):
                    raise RuntimeError(f"网络请求失败：{exc.reason}") from exc
                raise RuntimeError("服务响应无法解密或不是 JSON") from exc
        raise RuntimeError(f"请求失败：{last_exc}")


def default_parameters(code: str) -> dict[str, str]:
    now = datetime.now()
    return {
        "uuid": secrets.token_hex(16),
        "code": code,
        "recomm_code": "",
        "token": "",
        "version": "1.0.16",
        "package_name": "com.paraglider.paraglidervpn",
        "platform": "android",
        "product": "Paraglider",
        "device_brand": "xiaomi:12",
        "install_time": now.strftime("%Y-%m-%d %H:%M:%S"),
        "quest_time": str(int(time.time() * 1000)),
        "protocol": "1",
        "language": "zh",
    }


def generate_credentials() -> tuple[str, str]:
    username = "pg" + secrets.token_hex(6)
    password = "Pg!" + secrets.token_urlsafe(10) + "9"
    return username, password


def register_account(code: str = DEFAULT_CODE) -> None:
    for attempt in range(1, 4):
        username, password = generate_credentials()
        settings: dict[str, Any] = {
            "base_url": DEFAULT_BASE_URL,
            "account": {"username": username, "password": password},
            "parameters": default_parameters(code),
        }
        try:
            response = ApiClient(settings).request("/member/register", {"username": username, "password": password})
        except RuntimeError as e:
            print(f"第 {attempt} 次注册网络失败：{e}")
            if attempt == 3:
                raise
            continue

        if response.get("code") != 200:
            msg = response.get("message", response)
            print(f"第 {attempt} 次注册失败：{msg}")
            if attempt == 3:
                raise RuntimeError(f"注册失败：{msg}")
            continue

        result = response.get("result") or {}
        token = result.get("token")
        if not token:
            raise RuntimeError("注册响应中没有 token")
        settings["parameters"]["token"] = str(token)
        user_info = result.get("user_info") or {}
        settings["

