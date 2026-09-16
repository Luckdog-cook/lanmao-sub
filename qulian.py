#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
趣连固定订阅自动更新版 - 优化版
"""

import base64
import hashlib
import io
import json
import os
import random
import string
import sys
import threading
import time
import urllib.parse
import urllib.request
import argparse
import logging
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

USE_OCR_ENGINE = None
_DDDD_OCR_INSTANCE = None

try:
    import pytesseract
    USE_OCR_ENGINE = "tesseract"
except ImportError:
    try:
        import ddddocr
        USE_OCR_ENGINE = "ddddocr"
    except ImportError:
        pass

from PIL import Image, ImageSequence, ImageOps
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Util.Padding import pad, unpad

BASE_URLS = [
    "https://api2.zestlink.com:48574/vpn/api",
    "https://api.zestlink.com/vpn/api",
