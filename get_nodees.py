#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""YesVPN 节点获取脚本 —— 只输出一种可直接复制使用的格式:vless:// 链接。"""

import collections
import ipaddress
import json
import os
import re
import sys
import time
import unicodedata
import urllib.request
from urllib.parse import quote

try:
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

# --------------------------------------------------------------- 固定参数
AID = 'org.yes.appv3'
ENDPOINTS = [
    'http://hk.vliteapi.com',
    'http://39.107.117.174',
    'http://y.aaliveapp.top',
    'http://112.124.9.113:8081',
]
HEADERS = {
    'User-Agent': 'YesVPN/1.7.5 (Android)',
    'X-Aid': 'yes',
    'Accept': 'application/json',
}
SNI = 'itunes.apple.com'
WS_PATH = '/ws'
FP = 'chrome'
PORT = 443
OUT_FILE = 'nodes_vless.txt'
OUT_DIR = ''
TIER_BY_FLAG = {1: 'pro', 0: 'free'}

UUID_RE = re.compile(
