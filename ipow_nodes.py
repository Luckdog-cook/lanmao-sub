#!/usr/bin/env python3
"""iPoW.ai 全自动实时真实 IP 拉取脚本（ipow_nodes.py 融合版：v2 全功能 + v1 订阅输出）

【核心设计原则：100% 动态实时获取，绝无任何硬编码 IP】
1. **零内置静态 IP 字典**：不依赖任何硬编码 IP，官方换一万次 IP 也绝不失效。
2. **双轨实时真 IP 获取**：
   - VLESS-Reality：调用官方 DHT 接口 `/p2p-lite/v2/dht/capability`，
     纯 Python 实时解密 `encrypted_profile`，获取官方当下真实的物理落地 IP！
   - Hysteria2：从官方订阅数据 `sub.ipow.ai` 中实时提取当前物理落地 IP，
     并自动纠偏 SNI，符合 RFC 规范。
3. **100% 纯 Python 3 标准库（零依赖）**：
   - 内置纯 Python Keccak-256、Secp256k1 椭圆曲线签名、AES-256-GCM 解密引擎。
   - 手机 Termux 仅需 `pkg install python`，单文件拷入即跑，免 pip / 免 Rust / 免 C 编译！
4. **429 限流全自动换号续传**：
   - 逐节点拉取撞到 429 限流时，0.5 秒内自动生成新 Web3 钱包并无缝接力。
5. **安卓目录直通**：
   - 自动识别并保存到 `/sdcard/Download`，方便直接在 v2rayNG / Clash Meta 中导入。

【完整性修复（v2.1）】
- 瞬时失败（网络抖动/5xx/解密偶发失败/节点命中不匹配）现在会**自动重试**而非永久丢弃，
  只有在钱包轮换上限内仍无法拉取的节点才会被标记为「未能拉取」并汇总输出。
- 恢复「节点命中校验」：仅当服务端返回的就是请求的 node_id 时才接受，避免错收默认节点。
- 增加内层重试（MAX_INNER_RETRY），减少无谓的钱包额度消耗。
- 融合 v1 输出习惯：额外生成 `ipow.txt`（一行一个，VLESS + Hysteria2 混排，GitHub raw / 剪贴板导入友好）。
"""

import argparse
import base64
import json
import os
import random
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

for _s in (sys.stdout, sys.stderr):
    if hasattr(_s, 'reconfigure'):
        try:
            _s.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass

# ---------------------------------------------------------------------------
# 可选硬件加速检测（若系统装了库则加速，没装则 100% 走纯 Python 内置引擎）
# ---------------------------------------------------------------------------
try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

try:
    from eth_account import Account
    from eth_account.messages import encode_defunct
    _HAS_ETH_ACCOUNT = True
except ImportError:
    _HAS_ETH_ACCOUNT = False

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False

# ---------------------------------------------------------------------------
# 常量配置
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
API_BASE = 'https://ipow.ai'
USER_AGENT = 'Dart/3.10 (dart:io)'
SUB_USER_AGENT = 'ClashforWindows/0.19.23'
CLIENT_TYPE = 'android'
CLIENT_VERSION = '4.3.4'
CAPABILITY = 'vless-reality:no-flow'
CATALOG_PATH = '/v1/nodes'
FLOW_VISION = 'xtls-rprx-vision'

PROTOCOL_VARIANTS = (
    ('vless-reality', FLOW_VISION, '-reality'),
    ('vless-reality:no-flow', '', '-noflow'),
)
DEFAULT_SNI = 'www.cloudflare.com'
DEFAULT_FINGERPRINT = 'chrome'
MERGED_NODES_FILE = 'all_nodes.json'
WALLETS_FILE = 'auto_wallets.json'
IP_MAP_FILE = 'node_ip_map.json'

# 单个节点在一次钱包会话内的最大内层重试次数（应对瞬时抖动，避免无谓换号）
MAX_INNER_RETRY = 3

# 内置全量 62 个已知物理节点（单文件独立运行，无需外部 json）
KNOWN_PHYSICAL_NODES = [
    {"id": "gcp-australia-southeast1-1", "country_code": "AU", "country": "Australia", "city": "australia-southeast1-a", "status": "online"},
    {"id": "gcp-australia-southeast1-2", "country_code": "AU", "country": "Australia", "city": "australia-southeast1-b", "status": "online"},
    {"id": "gcp-europe-west1-1", "country_code": "BE", "country": "Belgium", "city": "Brussels", "status": "online"},
    {"id": "gcp-europe-west1-2", "country_code": "BE", "country": "Belgium", "city": "Brussels", "status": "online"},
    {"id": "gcp-europe-west1-be-1", "country_code": "BE", "country": "Belgium", "city": "europe-west1-b", "status": "online"},
    {"id": "gcp-europe-west1-be-2", "country_code": "BE", "country": "Belgium", "city": "europe-west1-c", "status": "online"},
    {"id": "gcp-southamerica-east1-1", "country_code": "BR", "country": "Brazil", "city": "southamerica-east1-a", "status": "online"},
    {"id": "gcp-southamerica-east1-2", "country_code": "BR", "country": "Brazil", "city": "southamerica-east1-a", "status": "online"},
    {"id": "gcp-northamerica-northeast1-1", "country_code": "CA", "country": "Canada", "city": "northamerica-northeast1-a", "status": "online"},
    {"id": "gcp-northamerica-northeast1-2", "country_code": "CA", "country": "Canada", "city": "northamerica-northeast1-b", "status": "online"},
    {"id": "gcp-europe-west6-1", "country_code": "CH", "country": "Switzerland", "city": "europe-west6-a", "status": "online"},
    {"id": "gcp-europe-west6-2", "country_code": "CH", "country": "Switzerland", "city": "europe-west6-b", "status": "online"},
    {"id": "gcp-southamerica-west1-cl-1", "country_code": "CL", "country": "Chile", "city": "southamerica-west1-a", "status": "online"},
    {"id": "gcp-southamerica-west1-cl-2", "country_code": "CL", "country": "Chile", "city": "southamerica-west1-b", "status": "online"},
    {"id": "gcp-europe-west3-1", "country_code": "DE", "country": "Germany", "city": "europe-west3-b", "status": "online"},
    {"id": "gcp-europe-west3-2", "country_code": "DE", "country": "Germany", "city": "europe-west3-c", "status": "online"},
    {"id": "gcp-europe-southwest1-es-1", "country_code": "ES", "country": "Spain", "city": "europe-southwest1-a", "status": "online"},
    {"id": "gcp-europe-southwest1-es-2", "country_code": "ES", "country": "Spain", "city": "europe-southwest1-b", "status": "online"},
    {"id": "gcp-europe-north1-fi-1", "country_code": "FI", "country": "Finland", "city": "europe-north1-a", "status": "online"},
    {"id": "gcp-europe-north1-fi-2", "country_code": "FI", "country": "Finland", "city": "europe-north1-b", "status": "online"},
    {"id": "gcp-europe-west9-1", "country_code": "FR", "country": "France", "city": "europe-west9-b", "status": "online"},
    {"id": "gcp-europe-west9-2", "country_code": "FR", "country": "France", "city": "europe-west9-b", "status": "online"},
    {"id": "gcp-europe-west2-1", "country_code": "GB", "country": "United Kingdom", "city": "europe-west2-b", "status": "online"},
    {"id": "gcp-europe-west2-2", "country_code": "GB", "country": "United Kingdom", "city": "europe-west2-a", "status": "online"},
    {"id": "gcp-asia-east2-1", "country_code": "HK", "country": "Hong Kong", "city": "asia-east2-a", "status": "online"},
    {"id": "gcp-asia-east2-2", "country_code": "HK", "country": "Hong Kong", "city": "asia-east2-b", "status": "online"},
    {"id": "gcp-asia-southeast2-1", "country_code": "ID", "country": "Indonesia", "city": "asia-southeast2-a", "status": "online"},
    {"id": "gcp-asia-southeast2-2", "country_code": "ID", "country": "Indonesia", "city": "asia-southeast2-b", "status": "online"},
    {"id": "gcp-me-west1-il-1", "country_code": "IL", "country": "Israel", "city": "me-west1-a", "status": "online"},
    {"id": "gcp-me-west1-il-2", "country_code": "IL", "country": "Israel", "city": "me-west1-b", "status": "online"},
    {"id": "gcp-asia-south1-1", "country_code": "IN", "country": "India", "city": "asia-south1-b", "status": "online"},
    {"id": "gcp-asia-south1-2", "country_code": "IN", "country": "India", "city": "asia-south1-c", "status": "online"},
    {"id": "gcp-europe-west8-it-1", "country_code": "IT", "country": "Italy", "city": "europe-west8-a", "status": "online"},
    {"id": "gcp-europe-west8-it-2", "country_code": "IT", "country": "Italy", "city": "europe-west8-b", "status": "online"},
    {"id": "gcp-asia-northeast1-1", "country_code": "JP", "country": "Japan", "city": "asia-northeast1-b", "status": "online"},
    {"id": "gcp-asia-northeast1-2", "country_code": "JP", "country": "Japan", "city": "asia-northeast1-c", "status": "online"},
    {"id": "gcp-asia-northeast3-1", "country_code": "KR", "country": "South Korea", "city": "asia-northeast3-a", "status": "online"},
    {"id": "gcp-asia-northeast3-2", "country_code": "KR", "country": "South Korea", "city": "asia-northeast3-b", "status": "online"},
    {"id": "gcp-northamerica-south1-mx-1", "country_code": "MX", "country": "Mexico", "city": "northamerica-south1-a", "status": "online"},
    {"id": "gcp-northamerica-south1-mx-2", "country_code": "MX", "country": "Mexico", "city": "northamerica-south1-b", "status": "online"},
    {"id": "gcp-europe-west4-1", "country_code": "NL", "country": "Netherlands", "city": "europe-west4-a", "status": "online"},
    {"id": "gcp-europe-west4-2", "country_code": "NL", "country": "Netherlands", "city": "europe-west4-b", "status": "online"},
    {"id": "gcp-europe-central2-pl-1", "country_code": "PL", "country": "Poland", "city": "Warsaw", "status": "online"},
    {"id": "gcp-europe-central2-pl-2", "country_code": "PL", "country": "Poland", "city": "Warsaw", "status": "online"},
    {"id": "gcp-me-central1-1", "country_code": "QA", "country": "Qatar", "city": "me-central1-a", "status": "online"},
    {"id": "gcp-me-central1-2", "country_code": "QA", "country": "Qatar", "city": "me-central1-b", "status": "online"},
    {"id": "gcp-europe-north2-1", "country_code": "SE", "country": "Sweden", "city": "europe-north2-b", "status": "online"},
    {"id": "gcp-europe-north2-2", "country_code": "SE", "country": "Sweden", "city": "europe-north2-c", "status": "online"},
    {"id": "gcp-asia-southeast1-1", "country_code": "SG", "country": "Singapore", "city": "Singapore", "status": "online"},
    {"id": "gcp-asia-southeast1-2", "country_code": "SG", "country": "Singapore", "city": "asia-southeast1-c", "status": "online"},
    {"id": "gcp-asia-southeast3-1", "country_code": "TH", "country": "Thailand", "city": "asia-southeast3-a", "status": "online"},
    {"id": "gcp-asia-southeast3-2", "country_code": "TH", "country": "Thailand", "city": "asia-southeast3-b", "status": "online"},
    {"id": "gcp-asia-east1-1", "country_code": "TW", "country": "Taiwan", "city": "asia-east1-a", "status": "online"},
    {"id": "gcp-asia-east1-2", "country_code": "TW", "country": "Taiwan", "city": "asia-east1-b", "status": "online"},
    {"id": "gcp-us-central1-1", "country_code": "US", "country": "United States", "city": "Council Bluffs", "status": "online"},
    {"id": "gcp-us-central1-2", "country_code": "US", "country": "United States", "city": "Council Bluffs", "status": "online"},
    {"id": "gcp-us-east4-1", "country_code": "US", "country": "United States", "city": "us-east4-b", "status": "online"},
    {"id": "gcp-us-east4-2", "country_code": "US", "country": "United States", "city": "us-east4-c", "status": "online"},
    {"id": "gcp-us-west1-1", "country_code": "US", "country": "United States", "city": "us-west1-b", "status": "online"},
    {"id": "gcp-us-west1-2", "country_code": "US", "country": "United States", "city": "us-west1-c", "status": "online"},
    {"id": "gcp-africa-south1-za-1", "country_code": "ZA", "country": "South Africa", "city": "africa-south1-a", "status": "online"},
    {"id": "gcp-africa-south1-za-2", "country_code": "ZA", "country": "South Africa", "city": "africa-south1-b", "status": "online"},
]


# ---------------------------------------------------------------------------
# 异常定义
# ---------------------------------------------------------------------------
class IpowError(RuntimeError):
    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code

class QuotaExhausted(IpowError):
    def __init__(self, detail=''):
        super().__init__(
            '配额已耗尽 (402)' + ('：' + detail if detail else ''),
            code='quota_exhausted')

class RateLimited(IpowError):
    def __init__(self, retry_after, detail=''):
        self.retry_after = max(int(retry_after or 0), 1)
        super().__init__('服务端限流 (429)，需等待 {} 秒{}'.format(
            self.retry_after, '：' + detail if detail else ''))

# ---------------------------------------------------------------------------
# 内置纯 Python 密码学模块 (100% 标准库)
# ---------------------------------------------------------------------------

# 1. Keccak-256
def _keccak_256(data: bytes) -> bytes:
    state = [[0] * 5 for _ in range(5)]
    RC = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
        0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]
    r_rot = [
        [0, 36, 3, 41, 18],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14],
    ]
    rate = 136
    pad_len = rate - (len(data) % rate)
    padded = data + (b'\x81' if pad_len == 1 else b'\x01' + b'\x00' * (pad_len - 2) + b'\x80')

    def rotl64(x, n):
        return ((x << (n % 64)) | (x >> (64 - (n % 64)))) & 0xFFFFFFFFFFFFFFFF

    for offset in range(0, len(padded), rate):
        block = padded[offset:offset + rate]
        for i in range(17):
            val = int.from_bytes(block[i * 8:(i + 1) * 8], 'little')
            state[i % 5][i // 5] ^= val

        for round_idx in range(24):
            C = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
            D = [C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1) for x in range(5)]
            for x in range(5):
                for y in range(5):
                    state[x][y] ^= D[x]

            B = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    B[y][(2 * x + 3 * y) % 5] = rotl64(state[x][y], r_rot[x][y])

            for x in range(5):
                for y in range(5):
                    state[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y])

            state[0][0] ^= RC[round_idx]

    out = bytearray()
    for i in range(4):
        val = state[i % 5][i // 5]
        out.extend(val.to_bytes(8, 'little'))
    return bytes(out)

# 2. Secp256k1
_SECP_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_SECP_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
)

def _point_add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and y1 != y2: return None
    if x1 == x2:
        m = (3 * x1 * x1 * pow(2 * y1, _SECP_P - 2, _SECP_P)) % _SECP_P
    else:
        m = ((y2 - y1) * pow(x2 - x1, _SECP_P - 2, _SECP_P)) % _SECP_P
    x3 = (m * m - x1 - x2) % _SECP_P
    y3 = (m * (x1 - x3) - y1) % _SECP_P
    return (x3, y3)

def _point_mul(p, k):
    res = None
    curr = p
    while k:
        if k & 1:
            res = _point_add(res, curr)
        curr = _point_add(curr, curr)
        k >>= 1
    return res

def _pure_private_key_to_address(priv_bytes) -> str:
    if isinstance(priv_bytes, str):
        raw_hex = priv_bytes[2:] if priv_bytes.startswith('0x') else priv_bytes
        priv_bytes = bytes.fromhex(raw_hex)
    k = int.from_bytes(priv_bytes, 'big')
    if not (1 <= k < _SECP_N):
        raise ValueError("Invalid private key")
    pt = _point_mul(_SECP_G, k)
    pub_uncompressed = pt[0].to_bytes(32, 'big') + pt[1].to_bytes(32, 'big')
    addr_hash = _keccak_256(pub_uncompressed)
    return '0x' + addr_hash[12:].hex()

def _pure_sign_personal_message(priv_bytes, message: str) -> str:
    if isinstance(priv_bytes, str):
        raw_hex = priv_bytes[2:] if priv_bytes.startswith('0x') else priv_bytes
        priv_bytes = bytes.fromhex(raw_hex)
    msg_bytes = message.encode('utf-8')
    prefix = f"\x19Ethereum Signed Message:\n{len(msg_bytes)}".encode('utf-8')
    h = _keccak_256(prefix + msg_bytes)
    e = int.from_bytes(h, 'big')
    d = int.from_bytes(priv_bytes, 'big')

    k_seed = _keccak_256(priv_bytes + h)
    k = (int.from_bytes(k_seed, 'big') % (_SECP_N - 1)) + 1

    pt = _point_mul(_SECP_G, k)
    r = pt[0] % _SECP_N
    s = (pow(k, _SECP_N - 2, _SECP_N) * (e + r * d)) % _SECP_N
    recid = pt[1] & 1
    if s > _SECP_N // 2:
        s = _SECP_N - s
        recid ^= 1
    v = 27 + recid

    return '0x' + r.to_bytes(32, 'big').hex() + s.to_bytes(32, 'big').hex() + bytes([v]).hex()


# 3. AES-256-GCM
_AES_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]
_RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

def _aes_key_expansion(key: bytes):
    nk = len(key) // 4
    nr = nk + 6
    w = list(key)
    i = nk
    while i < 4 * (nr + 1):
        temp = w[(i - 1) * 4: i * 4]
        if i % nk == 0:
            temp = [_AES_SBOX[temp[1]], _AES_SBOX[temp[2]], _AES_SBOX[temp[3]], _AES_SBOX[temp[0]]]
            temp[0] ^= _RCON[i // nk]
        elif nk > 6 and i % nk == 4:
            temp = [_AES_SBOX[b] for b in temp]
        for j in range(4):
            w.append(w[(i - nk) * 4 + j] ^ temp[j])
        i += 1
    return bytes(w), nr

def _xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1)

def _aes_encrypt_block(block: bytes, w: bytes, nr: int) -> bytes:
    state = list(block)
    for i in range(16): state[i] ^= w[i]
    for round_idx in range(1, nr):
        state = [_AES_SBOX[b] for b in state]
        s0, s4, s8, s12 = state[0], state[4], state[8], state[12]
        s1, s5, s9, s13 = state[5], state[9], state[13], state[1]
        s2, s6, s10, s14 = state[10], state[14], state[2], state[6]
        s3, s7, s11, s15 = state[15], state[3], state[7], state[11]
        for c, (r0, r1, r2, r3) in enumerate([(s0, s1, s2, s3), (s4, s5, s6, s7), (s8, s9, s10, s11), (s12, s13, s14, s15)]):
            t = r0 ^ r1 ^ r2 ^ r3
            state[c * 4] = r0 ^ t ^ _xtime(r0 ^ r1)
            state[c * 4 + 1] = r1 ^ t ^ _xtime(r1 ^ r2)
            state[c * 4 + 2] = r2 ^ t ^ _xtime(r2 ^ r3)
            state[c * 4 + 3] = r3 ^ t ^ _xtime(r3 ^ r0)
        round_key = w[round_idx * 16:(round_idx + 1) * 16]
        for i in range(16): state[i] ^= round_key[i]
    state = [_AES_SBOX[b] for b in state]
    state = [
        state[0], state[5], state[10], state[15],
        state[4], state[9], state[14], state[3],
        state[8], state[13], state[2], state[7],
        state[12], state[1], state[6], state[11]
    ]
    round_key = w[nr * 16:(nr + 1) * 16]
    for i in range(16): state[i] ^= round_key[i]
    return bytes(state)

def _ghash(h_bytes, data):
    h = int.from_bytes(h_bytes, 'big')
    r = 0xE1000000000000000000000000000000
    y = 0
    for i in range(0, len(data), 16):
        x = int.from_bytes(data[i:i+16], 'big')
        v = y ^ x
        z = 0
        for bit in range(128):
            if (h >> (127 - bit)) & 1:
                z ^= v
            if v & 1:
                v = (v >> 1) ^ r
            else:
                v >>= 1
        y = z
    return y.to_bytes(16, 'big')

def _pure_aes_gcm_decrypt(key: bytes, nonce: bytes, ct_and_tag: bytes, aad: bytes = b'') -> bytes:
    if len(nonce) != 12:
        raise ValueError('Nonce 长度必须为 12 字节')
    if len(ct_and_tag) < 16:
        raise ValueError('密文长度不足(缺少 Tag)')
    ct = ct_and_tag[:-16]
    expected_tag = ct_and_tag[-16:]

    w, nr = _aes_key_expansion(key)
    h_bytes = _aes_encrypt_block(b'\x00' * 16, w, nr)

    j0 = nonce + b'\x00\x00\x00\x01'
    j0_enc = _aes_encrypt_block(j0, w, nr)

    pad_aad = aad + b'\x00' * (-len(aad) % 16)
    pad_ct = ct + b'\x00' * (-len(ct) % 16)
    len_blk = (len(aad) * 8).to_bytes(8, 'big') + (len(ct) * 8).to_bytes(8, 'big')
    ghash_data = pad_aad + pad_ct + len_blk

    ghash_out = _ghash(h_bytes, ghash_data)
    computed_tag = bytes(a ^ b for a, b in zip(ghash_out, j0_enc))
    if computed_tag != expected_tag:
        raise ValueError('GCM 校验标签不匹配')

    counter = 2
    pt = bytearray()
    for i in range(0, len(ct), 16):
        cb = nonce + counter.to_bytes(4, 'big')
        ks = _aes_encrypt_block(cb, w, nr)
        block = ct[i:i+16]
        pt.extend(bytes(a ^ b for a, b in zip(block, ks[:len(block)])))
        counter += 1
    return bytes(pt)

# ---------------------------------------------------------------------------
# 格式化与辅助函数
# ---------------------------------------------------------------------------

def b64d(s):
    s = s.replace('-', '+').replace('_', '/')
    return base64.b64decode(s + '=' * (-len(s) % 4))

def country_code_from_node_id(node_id):
    m = re.search(r'-([a-z]{2})-\d+$', node_id or '')
    return m.group(1).upper() if m else None

def get_default_download_dir():
    """获取系统默认下载目录（安卓上自动使用 /sdcard/Download）"""
    if os.name == 'nt':
        win_dl = os.path.join(os.path.expanduser('~'), 'Downloads')
        if os.path.isdir(win_dl):
            return win_dl
        return BASE_DIR

    android_paths = [
        '/sdcard/Download',
        '/storage/emulated/0/Download',
        os.path.expanduser('~/storage/downloads'),
    ]
    for p in android_paths:
        if os.path.isdir(p) and os.access(p, os.W_OK):
            return p

    for parent in ['/sdcard', '/storage/emulated/0']:
        if os.path.isdir(parent):
            target = os.path.join(parent, 'Download')
            try:
                os.makedirs(target, exist_ok=True)
                if os.access(target, os.W_OK):
                    return target
            except Exception:
                pass

    user_dl = os.path.join(os.path.expanduser('~'), 'Downloads')
    if os.path.isdir(user_dl) and os.access(user_dl, os.W_OK):
        return user_dl

    return BASE_DIR

def write_json(path, obj):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write('\n')
    os.replace(tmp, path)

def is_ipv4(addr):
    if not addr or not isinstance(addr, str):
        return False
    parts = addr.strip().split('.')
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or not (0 <= int(p) <= 255):
            return False
    return True

# ---------------------------------------------------------------------------
# 网络客户端
# ---------------------------------------------------------------------------

class IpowClient:
    def __init__(self, base=API_BASE, timeout=20, verbose=False):
        self.base = base.rstrip('/')
        self.timeout = timeout
        self.verbose = verbose
        if _HAS_REQUESTS:
            self.session = requests.Session()
            self.session.headers.update({
                'User-Agent': USER_AGENT,
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            })
        else:
            self.session = None
            try:
                self.ssl_ctx = ssl.create_default_context()
            except Exception:
                self.ssl_ctx = ssl._create_unverified_context()

    def _request(self, method, path, body=None, token=None):
        url = self.base + path
        if self.verbose:
            shown = json.dumps(body, ensure_ascii=False)[:160] if body else ''
            print('  -> {} {} {}'.format(method, path, shown))

        if self.session is not None:
            headers = {'Authorization': 'Bearer ' + token} if token else {}
            r = self.session.request(method, url, json=body, headers=headers,
                                     timeout=self.timeout)
            status_code = r.status_code
            resp_headers = r.headers
            resp_text = r.text
        else:
            req_headers = {
                'User-Agent': USER_AGENT,
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            }
            if token:
                req_headers['Authorization'] = 'Bearer ' + token
            data_bytes = json.dumps(body).encode('utf-8') if body else None
            req = urllib.request.Request(url, data=data_bytes, headers=req_headers,
                                         method=method)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout,
                                            context=self.ssl_ctx) as resp:
                    status_code = resp.status
                    resp_headers = resp.headers
                    resp_text = resp.read().decode('utf-8', 'replace')
            except urllib.error.HTTPError as err:
                status_code = err.code
                resp_headers = err.headers
                resp_text = err.read().decode('utf-8', 'replace')
            except Exception as err:
                raise IpowError('网络请求失败: {}'.format(err))

        if self.verbose:
            print('  <- {} {}'.format(status_code, resp_text[:160]))

        if status_code == 429:
            raw = (resp_headers.get('Retry-After')
                   or resp_headers.get('retry-after') if resp_headers else None)
            try:
                retry_after = int(float(raw))
            except (TypeError, ValueError):
                retry_after = 200
            raise RateLimited(retry_after, resp_text[:120])

        if status_code == 402:
            raise QuotaExhausted(resp_text[:160])

        if status_code >= 400:
            code = None
            try:
                code = (json.loads(resp_text).get('error') or {}).get('code')
            except Exception:
                pass
            raise IpowError('HTTP {} {}: {}'.format(
                status_code, path, resp_text[:300]), code=code)

        try:
            return json.loads(resp_text)
        except Exception:
            raise IpowError('响应不是 JSON: ' + resp_text[:200])

    def challenge(self, address):
        return self._request('POST', '/v1/auth/wallet/challenge',
                             {'address': address})

    def verify(self, address, signature, nonce, device_id, device_name):
        return self._request('POST', '/v1/auth/wallet/verify', {
            'address': address,
            'signature': signature,
            'nonce': nonce,
            'device_id': device_id,
            'device_name': device_name,
            'client_type': CLIENT_TYPE,
        })

    def session_start(self, token, device_id, device_name):
        return self._request('POST', '/p2p-lite/v2/vpn/sessions/start', {
            'client_type': CLIENT_TYPE,
            'device_id': device_id,
            'device_name': device_name,
            'client_version': CLIENT_VERSION,
            'preferred_country': 'AUTO',
        }, token=token)

    def capability(self, token, session_id, country, subscription_token,
                   device_id, node_id=None):
        body = {
            'session_id': session_id,
            'client_type': CLIENT_TYPE,
            'device_id': device_id,
            'country': country,
            'capabilities': [CAPABILITY],
            'subscription_token': subscription_token,
            'allow_country_switch': True,
        }
        if node_id:
            body['node_id'] = node_id
        return self._request('POST', '/p2p-lite/v2/dht/capability',
                             body, token=token)

# ---------------------------------------------------------------------------
# 解密与配置生成
# ---------------------------------------------------------------------------

def node_name(node):
    return "iPoW-{}-{}{}".format(node.get('country_code', 'XX'),
                                 node['node_id'], node.get('name_suffix', ''))

def build_vless_url(node):
    name = node_name(node)
    fp = node.get('fingerprint') or DEFAULT_FINGERPRINT
    parts = [
        'encryption=none',
        'flow={}'.format(node.get('flow') or ''),
        'security=reality',
        'sni={}'.format(node.get('sni') or DEFAULT_SNI),
        'fp={}'.format(fp),
        'pbk={}'.format(node['public_key']),
        'sid={}'.format(node['short_id']),
        'type=tcp',
    ]
    return 'vless://{}@{}:{}?{}#{}'.format(
        node['uuid'], node['server'], node['port'], '&'.join(parts), name)

def build_hy2_url(node):
    hy2 = node.get('hy2') or {}
    server = hy2.get('server') or node['server']
    port = hy2.get('server_port') or node['port']
    sni = hy2.get('sni') or ''
    if is_ipv4(sni):
        sni = ''
    params = ['insecure=1']
    if sni:
        params.append('sni=' + urllib.parse.quote(str(sni)))
    query = '?' + '&'.join(params) if params else ''
    return 'hysteria2://{}@{}:{}/{}#{}'.format(
        hy2.get('password') or '', server, port, query, node_name(node))

def build_clash_yaml(nodes):
    lines = [
        '# Clash Meta / Mihomo Proxies Configuration (100% Live Dynamic IPs)',
        'proxies:',
    ]
    for n in nodes:
        lines.append("  - name: '{}'".format(node_name(n)))
        if n.get('protocol') == 'hysteria2':
            hy2 = n.get('hy2') or {}
            server = hy2.get('server') or n['server']
            lines.append('    type: hysteria2')
            lines.append('    server: {}'.format(server))
            lines.append('    port: {}'.format(hy2.get('server_port') or n['port']))
            lines.append('    password: {}'.format(hy2.get('password') or ''))
            sni = hy2.get('sni') or ''
            if sni and not is_ipv4(sni):
                lines.append('    sni: {}'.format(sni))
            lines.append('    skip-cert-verify: true')
            lines.append('    udp: true')
            continue
        lines.append('    type: vless')
        lines.append('    server: {}'.format(n['server']))
        lines.append('    port: {}'.format(n['port']))
        lines.append('    uuid: {}'.format(n['uuid']))
        lines.append('    network: tcp')
        if n.get('flow'):
            lines.append('    flow: {}'.format(n['flow']))
        lines.append('    tls: true')
        lines.append('    udp: true')
        lines.append('    servername: {}'.format(n.get('sni') or DEFAULT_SNI))
        lines.append('    client-fingerprint: {}'.format(
            n.get('fingerprint') or DEFAULT_FINGERPRINT))
        lines.append('    reality-opts:')
        lines.append("      public-key: '{}'".format(n['public_key']))
        lines.append("      short-id: '{}'".format(n['short_id']))
    return '\n'.join(lines)

def build_singbox_json(nodes):
    outbounds = []
    for n in nodes:
        if n.get('protocol') == 'hysteria2':
            hy2 = n.get('hy2') or {}
            server = hy2.get('server') or n['server']
            sni = hy2.get('sni') or ''
            tls_dict = {'enabled': True, 'insecure': True}
            if sni and not is_ipv4(sni):
                tls_dict['server_name'] = sni
            outbounds.append({
                'type': 'hysteria2',
                'tag': node_name(n),
                'server': server,
                'server_port': hy2.get('server_port') or n['port'],
                'password': hy2.get('password') or '',
                'tls': tls_dict,
            })
            continue
        outbounds.append({
            'type': 'vless',
            'tag': node_name(n),
            'server': n['server'],
            'server_port': n['port'],
            'uuid': n['uuid'],
            'packet_encoding': 'xudp',
            **({'flow': n['flow']} if n.get('flow') else {}),
            'tls': {
                'enabled': True,
                'server_name': n.get('sni') or DEFAULT_SNI,
                'utls': {
                    'enabled': True,
                    'fingerprint': n.get('fingerprint') or DEFAULT_FINGERPRINT,
                },
                'reality': {
                    'enabled': True,
                    'public_key': n['public_key'],
                    'short_id': n['short_id'],
                },
            },
        })
    return {'outbounds': outbounds}

def deduplicate_physical_nodes(nodes):
    by_id = {}
    for n in nodes:
        nid = n.get('node_id')
        if not nid:
            continue
        if nid not in by_id:
            base = dict(n)
            base.pop('name_suffix', None)
            base.pop('protocol', None)
            base.pop('flow', None)
            base.pop('vless_url', None)
            base.pop('hy2_url', None)
            by_id[nid] = base
        else:
            base = by_id[nid]
            if n.get('hy2') and not base.get('hy2'):
                base['hy2'] = n['hy2']
            if is_ipv4(n.get('server')) and not is_ipv4(base.get('server')):
                base['server'] = n['server']
    return list(by_id.values())

def expand_protocol_variants(nodes, with_vision=False):
    nodes = deduplicate_physical_nodes(nodes)
    expanded = []
    for n in nodes:
        # 1. 官方原生标准 VLESS Reality (无流控，100% 官方服务端兼容)
        v = dict(n)
        v['protocol'] = 'vless-reality:no-flow'
        v['flow'] = ''
        v['name_suffix'] = ''
        v['vless_url'] = build_vless_url(v)
        expanded.append(v)

        # 2. 仅在明确开启时才生成带 xtls-rprx-vision 流控变种
        if with_vision:
            v_vis = dict(n)
            v_vis['protocol'] = 'vless-reality'
            v_vis['flow'] = FLOW_VISION
            v_vis['name_suffix'] = '-reality'
            v_vis['vless_url'] = build_vless_url(v_vis)
            expanded.append(v_vis)

        # 3. 官方 Hysteria2 节点
        if n.get('hy2') and (n['hy2'] or {}).get('password'):
            v = dict(n)
            v['protocol'] = 'hysteria2'
            v['flow'] = ''
            v['name_suffix'] = '-hy2'
            v['vless_url'] = None
            v['hy2_url'] = build_hy2_url(v)
            expanded.append(v)
    return expanded

def write_configs(nodes, work_dir, with_vision=False, quiet=False):
    os.makedirs(work_dir, exist_ok=True)
    nodes = expand_protocol_variants(nodes, with_vision=with_vision)
    paths = {
        'json': os.path.join(work_dir, MERGED_NODES_FILE),
        'vless': os.path.join(work_dir, 'all_nodes_vless.txt'),
        'clash': os.path.join(work_dir, 'clash_proxies.yaml'),
        'singbox': os.path.join(work_dir, 'singbox_outbounds.json'),
    }
    vless_nodes = [n for n in nodes if n.get('protocol') != 'hysteria2']
    hy2_nodes = [n for n
