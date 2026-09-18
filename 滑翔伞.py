"""滑翔伞 VPN 接口客户端（仅用于已获授权的账户和服务）。

依赖：python -m pip install cryptography
运行：
  python 滑翔伞.py register          # 注册账户
  python 滑翔伞.py fetch             # 拉取全部 VIP 节点
  python 滑翔伞.py                   # 交互菜单（本地用）
"""

import argparse
import base64
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
REPLACED_AID = "1002"
DEFAULT_BASE_URL = "https://www.qajjzuyz.net:28075"
DEFAULT_CODE = "EJQRDBB"
SIGN_SUFFIX = "EbbubitewJxcPYpn"
NONCE_ALPHABET = string.ascii_letters + string.digits

# 此处会在构建时写入 gzip 压缩后的白盒表；运行时不依赖 .so 或外部数据文件。
WHITEBOX_TABLE_B64 = b"""
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
gmCF9BImz5Yxp4hRPk6Ck...(truncated)...
"""


class WhiteboxAes:
    """纯 Python 实现的 APK 白盒 AES-256 块函数。"""

    TABLE_SIZE = 0xB7000
    ROUND_INPUT = 0x00000
    ROUND_NETWORK = 0x34000
    ROUND_OUTPUT = 0x82000
    FINAL_ROUND = 0xB6000

    def __init__(self) -> None:
        self.tables = gzip.decompress(base64.b64decode(WHITEBOX_TABLE_B64))
        if len(self.tables) != self.TABLE_SIZE:
            raise ValueError(f"白盒 AES 表文件长度错误：{len(self.tables)}")

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
        settings["parameters"]["code"] = str(user_info.get("code") or settings["parameters"]["code"])
        CONFIG_PATH.write_text(json.dumps(settings, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"注册成功：{username} / {password}")
        print(f"后续取节点参数已保存到：{CONFIG_PATH}")
        return


def load_settings() -> dict[str, Any]:
    if not CONFIG_PATH.is_file():
        raise FileNotFoundError(f"找不到 {CONFIG_PATH.name}，请先执行 register 注册账户")
    settings = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    if not settings.get("parameters", {}).get("token"):
        raise ValueError(f"{CONFIG_PATH.name} 中没有 token")
    return settings


def collect_lines(response: dict[str, Any]) -> list[tuple[str, str, str]]:
    result = response.get("result") or {}
    lines: list[tuple[str, str, str]] = []
    for country_group in result.get("vip", []) or []:
        country = country_group.get("country", {}).get("name", "VIP")
        for line in country_group.get("linelist", []) or []:
            if line.get("enable") != 1:
                continue
            line_id = str(line.get("id", ""))
            if line_id:
                lines.append(("vip", str(country), line_id))
    return lines


def fetch_all_nodes() -> None:
    settings = load_settings()
    client = ApiClient(settings)
    line_response = client.request("/entity/linelist")
    if line_response.get("code") != 200:
        raise RuntimeError(f"获取线路失败：{line_response.get('message', line_response)}")

    lines = collect_lines(line_response)
    if not lines:
        raise RuntimeError("线路列表为空")
    output: list[str] = []
    success = 0
    for index, (group_name, country, line_id) in enumerate(lines, start=1):
        print(f"[{index}/{len(lines)}] 获取 {country}（线路 {line_id}）…")
        try:
            response = client.request("/entity/nodeinfo", {"line_id": line_id})
            if response.get("code") != 200:
                print(f"  失败：{response.get('message', '未知错误')}")
                continue
            result = response.get("result") or {}
            node_config = decrypt_node_payload(str(result["nodedata"]))
            output.append(vmess_link(node_config, f"滑翔伞-{country}-{line_id}"))
            success += 1
        except Exception as exc:
            print(f"  失败：{exc}")

    OUTPUT_PATH.write_text("\n".join(output) + "\n", encoding="utf-8")
    print(f"完成：成功获取 {success}/{len(lines)} 个 VIP 地区节点（未包含 Free）。")
    print(f"节点链接已保存：{OUTPUT_PATH}")


def interactive_menu() -> None:
    while True:
        print("\n滑翔伞接口工具\n1. 注册账户并保存参数\n2. 一次性获取全部 VIP 地区节点\n0. 退出")
        try:
            choice = input("请选择：").strip()
        except EOFError:
            print("检测到非交互环境，请使用命令行参数：")
            print("  python 滑翔伞.py register")
            print("  python 滑翔伞.py fetch")
            sys.exit(1)

        try:
            if choice == "1":
                register_account()
            elif choice == "2":
                fetch_all_nodes()
            elif choice == "0":
                return
            else:
                print("请输入 0、1 或 2")
        except (FileNotFoundError, RuntimeError, ValueError) as exc:
            print(f"操作失败：{exc}")


def main() -> None:
    parser = argparse.ArgumentParser(description="滑翔伞 VPN 接口客户端")
    parser.add_argument(
        "command",
        nargs="?",
        choices=["register", "fetch"],
        help="register=注册账户, fetch=拉取全部VIP节点。不传参数则进入交互菜单",
    )
    parser.add_argument(
        "--code",
        default=DEFAULT_CODE,
        help=f"注册时使用的邀请码（默认 {DEFAULT_CODE}）",
    )
    args = parser.parse_args()

    try:
        if args.command == "register":
            register_account(code=args.code)
        elif args.command == "fetch":
            fetch_all_nodes()
        else:
            interactive_menu()
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"操作失败：{exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
