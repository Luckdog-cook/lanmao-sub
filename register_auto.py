# -*- coding: utf-8 -*-
"""
账号自动注册 · 验证码自动识别版（单文件）

只需要这一个文件。首次运行会自动安装缺少的依赖，之后不再检查。
识别优先级：ddddocr  ->  模板匹配  ->  自动换图重试（全程无需人工）
"""
import sys
import os
import subprocess

# ============ 依赖自举：缺什么自动装什么（只做一次） ============
_MIRROR = "https://pypi.tuna.tsinghua.edu.cn/simple"
_FLAG = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.deps_ok')


def _pip_install(pkgs):
    try:
        subprocess.run(
            [sys.executable, '-m', 'pip', 'install', *pkgs, '-i', _MIRROR],
            check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except Exception:
        pass


def _has(mod):
    try:
        __import__(mod)
        return True
    except Exception:
        return False


def _find_tesseract():
    """定位 tesseract 可执行文件，找不到返回 None"""
    import shutil
    p = shutil.which('tesseract') or shutil.which('tesseract.exe')
    if p:
        return p
    for c in [
        '/data/data/com.termux/files/usr/bin/tesseract',   # Termux
        '/usr/bin/tesseract', '/usr/local/bin/tesseract',   # Linux/macOS
        r'C:\Program Files\Tesseract-OCR\tesseract.exe',
        r'C:\Program Files (x86)\Tesseract-OCR\tesseract.exe',
    ]:
        if os.path.exists(c):
            return c
    return None


def _in_termux():
    """是否运行在 Termux（Android）环境"""
    return 'com.termux' in os.environ.get('PREFIX', '') or os.path.exists('/data/data/com.termux')


def ensure_deps():
    """首次运行自动补齐依赖；已装则跳过"""
    if os.path.exists(_FLAG):
        return
    termux = _in_termux()

    if termux and not _has('PIL'):
        print("[Termux] 检测到 Termux 环境，优先用 pkg 安装 Pillow（更稳）...")
        try:
            subprocess.run(['pkg', 'install', 'python-pillow', '-y'],
                           check=False, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=600)
        except Exception:
            pass

    need = []
    if not _has('requests'):
        need.append('requests')
    if not _has('PIL'):
        need.append('pillow')
    if not _has('ddddocr'):
        need.append('ddddocr')

    if need:
        print("[首次运行] 正在自动安装依赖：" + "、".join(need))
        print("           使用国内镜像，约 1-3 分钟，请耐心等待...")
        _pip_install(need)
        print("[首次运行] 安装完成\n")

    if termux and not _has('ddddocr'):
        print("[Termux] ddddocr 不可用（Android 无预编译包），属正常现象")
        if not _find_tesseract():
            print("[Termux] 正在安装替补引擎 tesseract（pkg install tesseract）...")
            try:
                subprocess.run(['pkg', 'install', 'tesseract', '-y'],
                               check=False, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=600)
                subprocess.run(['pip', 'install', 'pytesseract', '-i', _MIRROR],
                               check=False, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=300)
            except Exception:
                pass
            if _find_tesseract():
                print("[Termux] tesseract 就绪 → 可全自动，无需人工攒样本\n")
            else:
                print("[Termux] tesseract 未装上，将用人工输入攒样本后转全自动")
                print("         手动装：pkg install tesseract && pip install pytesseract\n")
        else:
            print("[Termux] 检测到 tesseract，可用作替补引擎\n")

    try:
        open(_FLAG, 'w').write('ok')
    except Exception:
        pass


ensure_deps()

try:
    import requests
    from PIL import Image
except ImportError as _e:
    print("\n[错误] 必需依赖未安装成功：" + str(_e))
    print("请手动执行以下命令后重新运行：")
    print(f"  pip install requests pillow -i {_MIRROR}")
    if sys.platform.startswith('win'):
        os.system('pause')
    sys.exit(1)

import base64
import random
import string
import time
import hashlib
from io import BytesIO

if sys.platform.startswith('win'):
    try:
        os.system('chcp 65001 >nul')
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# ================= 接口配置（与火种抓包一致） =================
GENERATE_URL = 'https://47.76.166.180/captcha/generate'
VALIDATE_URL = 'https://47.76.166.180/captcha/validate'
REGISTER_URL = 'https://47.76.166.180/users'

AUTH_URL = 'https://154.17.1.102/realms/vpn_application/protocol/openid-connect/token'
CLIENT_ID = 'vpn-user'
CLIENT_SECRET = 'i16bYq4sXxlGl3s'

HEADERS = {
    'User-Agent': 'ktor-client',
    'Accept': 'application/json',
    'Accept-Encoding': 'gzip',
    'Content-Type': 'application/json',
    'X-App-Version': '1.1.21',
    'X-Device-OS': 'Android',
}

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
VERIFY_SSL = False

ACCOUNTS_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    'huozhong_accounts.txt',
)

# ================= 自定义配置 =================
USERNAME_LEN = 10
PASSWORD_LEN = 10
DEVICEID_LEN = 16
RETRY_TIMES = 60
REFERRAL_CODE = "pcxmbvb"
CHAR_SET = string.ascii_lowercase + string.digits
NEVER_ASK = True
ASK_AFTER = 10
CAPTCHA_LEN = 5
TEMPLATE_MAX_DIFF = 0.30
VOTE_ROUNDS = 4

DIGITS_ONLY = True
_CONFUSION = {'O': '0', 'o': '0', 'D': '0', 'Q': '0',
              'I': '1', 'l': '1', 'i': '1', '|': '1', 'L': '1',
              'Z': '2', 'z': '2', 'S': '5', 's': '5',
              'G': '6', 'b': '6', 'B': '8', 'T': '7',
              'q': '9', 'g': '9', 'A': '4'}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(BASE_DIR, 'captcha_samples')
os.makedirs(SAMPLES, exist_ok=True)

SAMPLE_DIR = None
TEMPLATE_SIZE = (16, 20)


def otsu_threshold(img):
    hist = img.histogram()
    total = sum(hist)
    sum_all = sum(i * h for i, h in enumerate(hist))
    sum_b = 0
    w_b = 0
    max_var = 0
    best = 127
    for t in range(256):
        w_b += hist[t]
        if w_b == 0:
            continue
        w_f = total - w_b
        if w_f == 0:
            break
        sum_b += t * hist[t]
        m_b = sum_b / w_b
        m_f = (sum_all - sum_b) / w_f
        var = w_b * w_f * (m_b - m_f) ** 2
        if var > max_var:
            max_var = var
            best = t
    return best


def denoise(img):
    w, h = img.size
    px = img.load()
    out = img.copy()
    op = out.load()
    for y in range(h):
        for x in range(w):
            if px[x, y] < 128:
                cnt = 0
                for dx in (-1, 0, 1):
                    for dy in (-1, 0, 1):
                        nx, ny = x + dx, y + dy
                        if 0 <= nx < w and 0 <= ny < h and px[nx, ny] < 128:
                            cnt += 1
                if cnt <= 2:
                    op[x, y] = 255
    return out


def to_binary(img):
    img = img.convert('L')
    t = otsu_threshold(img)
    img = img.point(lambda x: 255 if x > t else 0, 'L')
    img = denoise(img)
    return img


def split_chars(binary, min_width=3, expect=None):
    w, h = binary.size
    px = binary.load()
    col_black = [sum(1 for y in range(h) if px[x, y] < 128) for x in range(w)]

    segs = []
    start = None
    for x in range(w):
        if col_black[x] > 0 and start is None:
            start = x
        elif col_black[x] == 0 and start is not None:
            segs.append((start, x))
            start = None
    if start is not None:
        segs.append((start, w))

    segs = [s for s in segs if s[1] - s[0] >= min_width]

    if expect and len(segs) < expect:
        merged = []
        for (a, b) in segs:
            width = b - a
            est = max(1, round(width / ((w / max(1, len(segs))) / expect)))
            if est > 1 and width / est > min_width * 2:
                step = width / est
                for i in range(est):
                    merged.append((int(a + i * step), int(a + (i + 1) * step)))
            else:
                merged.append((a, b))
        segs = merged
    return segs


def normalize_char(binary, box):
    x0, x1 = box
    w, h = binary.size
    px = binary.load()
    rows = [y for y in range(h) if any(px[x, y] < 128 for x in range(x0, x1))]
    if not rows:
        return None
    char = binary.crop((x0, min(rows), x1, max(rows) + 1))
    return char.resize(TEMPLATE_SIZE, Image.LANCZOS)


def diff_score(a, b, shift=2):
    pa, pb = a.load(), b.load()
    W, H = TEMPLATE_SIZE
    best = 1.0
    for dy in range(-shift, shift + 1):
        for dx in range(-shift, shift + 1):
            diff = 0
            for y in range(H):
                for x in range(W):
                    xx, yy = x + dx, y + dy
                    vb = 1 if (0 <= xx < W and 0 <= yy < H and pb[xx, yy] < 128) else 0
                    va = 1 if pa[x, y] < 128 else 0
                    if va != vb:
                        diff += 1
            s = diff / (W * H)
            if s < best:
                best = s
    return best


_templates = None
_template_loaded = False


def load_templates(sample_dir):
    global _templates, _template_loaded
    if not sample_dir or not os.path.isdir(sample_dir):
        _template_loaded = True
        return
    _templates = {}
    for fn in os.listdir(sample_dir):
        if not fn.lower().endswith('.png'):
            continue
        parts = fn[:-4].split('_')
        if len(parts) < 2:
            continue
        label = parts[1]
        if not label or not label.isalnum():
            continue
        try:
            img = Image.open(os.path.join(sample_dir, fn))
            binary = to_binary(img)
            boxes = split_chars(binary, expect=len(label))
            if len(boxes) != len(label):
                continue
            for ch, box in zip(label, boxes):
                norm = normalize_char(binary, box)
                if norm:
                    _templates.setdefault(ch, []).append(norm)
        except Exception:
            continue
    _template_loaded = True


def match_by_template(binary, expect=None):
    if not _template_loaded:
        load_templates(SAMPLE_DIR)
    if not _templates:
        return None, 1.0

    boxes = split_chars(binary, expect=expect)
    if not boxes:
        return None, 1.0

    result = []
    total = 0.0
    for box in boxes:
        norm = normalize_char(binary, box)
        if not norm:
            continue
        best_ch, best_score = None, 1.0
        for ch, tpls in _templates.items():
            for tpl in tpls:
                s = diff_score(norm, tpl)
                if s < best_score:
                    best_score, best_ch = s, ch
        if best_ch:
            result.append(best_ch)
            total += best_score
    if not result:
        return None, 1.0
    return ''.join(result), total / len(result)
# ============ ddddocr ============
_ddddocr = None
_ddddocr_failed = False


def get_ddddocr():
    global _ddddocr, _ddddocr_failed
    if _ddddocr_failed:
        return None
    if _ddddocr is None:
        try:
            import ddddocr
            _ddddocr = ddddocr.DdddOcr(show_ad=False)
            if DIGITS_ONLY:
                try:
                    _ddddocr.set_ranges('0123456789')
                except Exception:
                    pass
        except Exception:
            _ddddocr_failed = True
            return None
    return _ddddocr


def match_by_ddddocr(image_bytes):
    ocr = get_ddddocr()
    if not ocr:
        return None
    try:
        res = ocr.classification(image_bytes)
        return res.strip() if res else None
    except Exception:
        return None


# ============ 多版本预处理 + 投票 ============
_known_len = CAPTCHA_LEN if CAPTCHA_LEN else None
_total_attempts = 0
_no_engine = False


def make_variants(image_bytes):
    variants = []
    try:
        orig = Image.open(BytesIO(image_bytes))
        w, h = orig.size
        variants.append(('raw', image_bytes))
        variants.append(('x2', _to_png(orig.resize((w * 2, h * 2), Image.LANCZOS))))
        gray = orig.convert('L')
        variants.append(('gray', _to_png(gray)))
        bin_img = to_binary(orig)
        variants.append(('otsu', _to_png(bin_img)))
        variants.append(('otsu_x2', _to_png(
            bin_img.resize((bin_img.width * 2, bin_img.height * 2), Image.LANCZOS))))
    except Exception:
        pass
    return variants


def _to_png(img):
    buf = BytesIO()
    img.save(buf, format='PNG')
    return buf.getvalue()


def _clean(code):
    if not code:
        return None
    code = code.strip()
    if DIGITS_ONLY:
        out = []
        for ch in code:
            if ch.isdigit():
                out.append(ch)
            elif ch in _CONFUSION:
                out.append(_CONFUSION[ch])
        return ''.join(out) or None
    return ''.join(ch for ch in code if ch.isalnum()) or None


def _plausible(code, expect):
    if not code:
        return False
    if expect:
        return len(code) == expect
    return 4 <= len(code) <= 6


def vote(codes, expect):
    valid = [c for c in codes if _plausible(c, expect)]
    if not valid:
        return None, 0, 0
    counts = {}
    for c in valid:
        counts[c] = counts.get(c, 0) + 1
    best = max(counts.items(), key=lambda kv: kv[1])
    return best[0], best[1], len(valid)


_tesseract_path = None
_tess_ok = None


def get_tesseract():
    global _tesseract_path, _tess_ok
    if _tess_ok is not None:
        return _tess_ok
    _tess_ok = None
    try:
        import pytesseract
        if _tesseract_path is None:
            _tesseract_path = _find_tesseract()
        if _tesseract_path:
            pytesseract.pytesseract.tesseract_cmd = _tesseract_path
            pytesseract.get_tesseract_version()
            _tess_ok = pytesseract
    except Exception:
        _tess_ok = None
    return _tess_ok


def tesseract_voting(image_bytes, expect=None):
    pt = get_tesseract()
    if not pt:
        return None, 0
    variants = make_variants(image_bytes)[:3]
    codes = []
    whitelist = ('0123456789' if DIGITS_ONLY
                 else '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
    for name, vb in variants:
        try:
            img = Image.open(BytesIO(vb))
            if img.mode != 'L':
                img = img.convert('L')
            t = otsu_threshold(img)
            img = img.point(lambda x: 255 if x > t else 0, 'L')
            img = img.resize((img.width * 3, img.height * 3), Image.LANCZOS)
            res = pt.image_to_string(
                img, config=f'--psm 7 -c tessedit_char_whitelist={whitelist}')
            c = _clean(res)
            if c:
                codes.append(c)
        except Exception:
            continue
    code, hits, total = vote(codes, expect)
    return code, hits


def ddddocr_voting(image_bytes, expect=None, rounds=VOTE_ROUNDS):
    ocr = get_ddddocr()
    if not ocr:
        return None, 0
    variants = make_variants(image_bytes)[:max(1, rounds)]
    codes = []
    for name, vb in variants:
        try:
            res = ocr.classification(vb)
            c = _clean(res)
            if c:
                codes.append(c)
        except Exception:
            continue
    code, hits, total = vote(codes, expect)
    return code, hits


def template_voting(image_bytes, expect=None, rounds=VOTE_ROUNDS):
    best_code, best_score = None, 1.0
    try:
        orig = Image.open(BytesIO(image_bytes))
        bins = [to_binary(orig)]
        big = orig.resize((orig.width * 2, orig.height * 2), Image.LANCZOS)
        bins.append(to_binary(big))
        for b in bins[:max(1, rounds)]:
            try:
                c, s = match_by_template(b, expect=expect)
                if c and _plausible(c, expect) and s < best_score:
                    best_code, best_score = c, s
            except Exception:
                continue
    except Exception:
        pass
    return best_code, best_score


_hash_index = None
_hash_index_loaded = False


def img_hashes(image_bytes):
    exact = hashlib.md5(image_bytes).hexdigest()
    shape = None
    try:
        img = Image.open(BytesIO(image_bytes)).convert('L').resize((16, 16), Image.LANCZOS)
        px = list(img.getdata())
        avg = sum(px) / len(px)
        bits = ''.join('1' if v > avg else '0' for v in px)
        shape = '%016x' % int(bits, 2)
    except Exception:
        pass
    return exact, shape


def build_hash_index():
    global _hash_index, _hash_index_loaded
    _hash_index = {}
    try:
        for fn in os.listdir(SAMPLES):
            if not fn.lower().endswith('.png') or not fn.startswith('captcha_'):
                continue
            parts = fn[:-4].split('_')
            if len(parts) < 2 or not parts[1]:
                continue
            code = parts[1]
            path = os.path.join(SAMPLES, fn)
            try:
                with open(path, 'rb') as f:
                    data = f.read()
                ex, sh = img_hashes(data)
                _hash_index['e:' + ex] = code
                if sh:
                    _hash_index.setdefault('s:' + sh, code)
            except Exception:
                continue
    except Exception:
        pass
    _hash_index_loaded = True


def lookup_by_hash(image_bytes, expect=None):
    global _hash_index_loaded
    if not _hash_index_loaded:
        build_hash_index()
    if not _hash_index:
        return None
    ex, sh = img_hashes(image_bytes)
    code = _hash_index.get('e:' + ex)
    if not code and sh:
        code = _hash_index.get('s:' + sh)
    if code and _plausible(code, expect):
        return code
    return None


def auto_recognize(image_bytes, expect=None):
    try:
        code = lookup_by_hash(image_bytes, expect=expect)
        if code:
            return code, '查表', 1.0
    except Exception:
        pass

    try:
        code, hits = ddddocr_voting(image_bytes, expect=expect)
        if code:
            return code, 'ddddocr', 1.0 if hits >= 2 else 0.5
    except Exception:
        pass

    try:
        code, hits = tesseract_voting(image_bytes, expect=expect)
        if code:
            return code, 'tesseract', 1.0 if hits >= 2 else 0.4
    except Exception:
        pass

    try:
        code, score = template_voting(image_bytes, expect=expect)
        if code and score < TEMPLATE_MAX_DIFF:
            return code, 'template', 1.0 - score
    except Exception:
        pass

    try:
        ocr = get_ddddocr()
        if ocr:
            c = _clean(ocr.classification(image_bytes))
            if _plausible(c, expect):
                return c, 'ddddocr', 0.3
    except Exception:
        pass

    return None, None, 0.0
SAMPLE_DIR = SAMPLES

def random_str(n):
    return ''.join(random.choice(CHAR_SET) for _ in range(n))


def gen_random_info():
    return {
        "username": random_str(USERNAME_LEN),
        "password": random_str(PASSWORD_LEN),
        "firstName": None,
        "lastName": None,
        "email": None,
        "appliedReferralCode": REFERRAL_CODE,
        "deviceId": random_str(DEVICEID_LEN),
    }


def get_captcha():
    resp = requests.get(GENERATE_URL, headers=HEADERS, timeout=10, verify=VERIFY_SSL)
    resp.raise_for_status()
    data = resp.json()
    return data['captchaId'], data['imageBase64']


def render_blocks(image, width=56):
    img = to_binary(image)
    w, h = img.size
    img = img.resize((w * 4, h * 4), Image.LANCZOS)
    w, h = img.size
    new_h = max(2, int(h / w * width))
    if new_h % 2:
        new_h += 1
    img = img.resize((width, new_h), Image.LANCZOS)
    px = img.load()
    lines = []
    for y in range(0, new_h, 2):
        row = []
        for x in range(width):
            top = px[x, y] < 128
            bot = px[x, y + 1] < 128 if y + 1 < new_h else False
            row.append('█' if top and bot else ('▀' if top else ('▄' if bot else ' ')))
        lines.append(''.join(row))
    return lines


def save_temp(image_base64, tag):
    path = os.path.join(SAMPLES, f'_tmp_{tag}_{random_str(4)}.png')
    with open(path, 'wb') as f:
        f.write(base64.b64decode(image_base64))
    return path


def archive_sample(path, code):
    if not (path and os.path.exists(path)):
        return
    try:
        dst = os.path.join(SAMPLES, f'captcha_{code}_{random_str(5)}.png')
        os.replace(path, dst)
        global _template_loaded
        _template_loaded = False
    except Exception:
        pass


def discard_sample(path):
    try:
        if path and os.path.exists(path):
            os.remove(path)
    except Exception:
        pass


def recognize(image_base64, tag):
    raw = base64.b64decode(image_base64)
    code, way, score = auto_recognize(raw)
    if code:
        print(f"🤖 自动识别[{way}]: {code}" + (f" (差异{score:.2f})" if way == 'template' else ""))
        return code, way, None
    return None, None, save_temp(image_base64, tag)


def ask_human(image_base64, path):
    img = Image.open(BytesIO(base64.b64decode(image_base64)))
    print("┌" + "─" * 56 + "┐")
    for line in render_blocks(img):
        print("│" + line + "│")
    print("└" + "─" * 56 + "┘")
    print("💡 易混：0/O  1/I/l  2/Z  5/S  6/G  8/B")
    return input("⌨️  自动识别失败，请手动输入（回车=换一张重试）：").strip() or None


def validate_captcha(captcha_id, user_input):
    data = {"captchaId": captcha_id, "userInput": user_input}
    resp = requests.post(VALIDATE_URL, headers=HEADERS, json=data, timeout=10, verify=VERIFY_SSL)
    resp.raise_for_status()
    result = resp.json()
    return result, result.get('token')


def user_register(token, reg_info):
    url = f"{REGISTER_URL}?captchaToken={token}"
    resp = requests.post(url, headers=HEADERS, json=reg_info, timeout=10, verify=VERIFY_SSL)
    resp.raise_for_status()
    return resp.json()


def login_verify(username, password):
    payload = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "password",
        "username": username,
        "password": password,
    }
    headers = {
        **HEADERS,
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    }
    try:
        resp = requests.post(AUTH_URL, data=payload, headers=headers, timeout=12, verify=VERIFY_SSL)
        if resp.status_code == 200:
            data = resp.json()
            token = data.get("access_token")
            if token:
                return token
        print(f"  [!] 登录验证失败 status={resp.status_code} body={resp.text[:200]}")
    except Exception as e:
        print(f"  [!] 登录验证异常: {e}")
    return None


def save_account(username, password, user_id=None):
    try:
        line = f"{username}\t{password}"
        if user_id is not None:
            line += f"\t{user_id}"
        line += "\n"
        with open(ACCOUNTS_FILE, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception as e:
        print(f"  [!] 写账号文件失败: {e}")


def save_success_sample(image_base64, code):
    global _template_loaded, _hash_index_loaded
    try:
        raw = base64.b64decode(image_base64)
        _ex, _sh = img_hashes(raw)
        if _hash_index_loaded and _hash_index:
            if ('e:' + _ex) in _hash_index or (_sh and ('s:' + _sh) in _hash_index):
                return
        path = os.path.join(SAMPLES, f'captcha_{code}_{random_str(5)}.png')
        with open(path, 'wb') as f:
            f.write(raw)
        _template_loaded = False
        _hash_index_loaded = False
    except Exception:
        pass


def single_register(reg_info):
    global _known_len, _total_attempts
    for retry in range(1, RETRY_TIMES + 1):
        try:
            cid, b64 = get_captcha()
            raw = base64.b64decode(b64)
            code, way, conf = auto_recognize(raw, expect=_known_len)

            _threshold = 1 if _no_engine else ASK_AFTER
            _want_ask = (not NEVER_ASK) and retry >= _threshold

            if code:
                res, token = validate_captcha(cid, code)
                if res.get('valid'):
                    if not _known_len:
                        _known_len = len(code)
                    save_success_sample(b64, code)
                    _total_attempts += retry
                    print(f"🤖 识别[{way}] {code} → ✅ 验证通过（第{retry}次尝试）")
                    return user_register(token, reg_info)

            if _want_ask:
                hc = ask_human(b64, None)
                if hc:
                    res, token = validate_captcha(cid, hc)
                    if res.get('valid'):
                        if not _known_len:
                            _known_len = len(hc)
                        save_success_sample(b64, hc)
                        _total_attempts += retry
                        print(f"✍️  人工输入 {hc} → ✅ 验证通过（第{retry}次尝试）")
                        return user_register(token, reg_info)

            if retry % 10 == 0:
                _why = f"上次识别 {code} 未通过" if code else "自动识别无结果"
                print(f"  … 已试{retry}次（{_why}），持续换图中")
            continue

        except Exception:
            continue

    raise Exception(f"连续{RETRY_TIMES}次未通过，建议检查识别引擎是否安装")


if __name__ == '__main__':
    print("===== 账号自动注册 [全自动验证码版] =====")
    ocr = get_ddddocr()
    if ocr:
        print("🟢 识别引擎：ddddocr 已就绪 → 全程无需人工")
        print(f"   多变体投票：每次生成 {VOTE_ROUNDS} 种预处理分别识别后投票")
    else:
        n = sum(1 for f in os.listdir(SAMPLES) if f.startswith('captcha_'))
        print("🟡 ddddocr 不可用，当前只有模板匹配，成功率偏低")
        print("   建议手动装一次（装完重启本脚本即可）：")
        print("   pip install ddddocr -i https://pypi.tuna.tsinghua.edu.cn/simple")
        print(f"   已积累样本：{n} 张")
    if not ocr:
        _tess = get_tesseract()
        if _tess:
            print("🟡 ddddocr 不可用，已启用替补引擎 tesseract")
        else:
            print("🟡 ddddocr 与 tesseract 均不可用，只能靠模板匹配")
    print(f"   模式：{'全自动（永不询问）' if NEVER_ASK else f'失败{ASK_AFTER}次后转人工'}"
          f" | 每个账号最多换图 {RETRY_TIMES} 次")

    _n_samples = 0
    try:
        _n_samples = sum(1 for f in os.listdir(SAMPLES)
                         if f.startswith('captcha_') and f.lower().endswith('.png'))
    except Exception:
        pass
    _has_engine = bool(get_ddddocr()) or bool(get_tesseract())
    if not _has_engine and _n_samples < 3:
        _no_engine = True
        print("\n⚠ 当前无法识别验证码（冷启动）")
        if NEVER_ASK:
            if os.environ.get("CI") or os.environ.get("REGISTER_COUNT") or (len(sys.argv) > 1 and sys.argv[1].isdigit()):
                print("非交互模式且无识别引擎，退出。")
                sys.exit(1)
            try:
                _c = input("仍要继续吗？（y=继续 / 回车=退出）：")
                if _c.strip().lower() != 'y':
                    sys.exit(0)
            except EOFError:
                sys.exit(0)

    total = None
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        total = int(sys.argv[1])
    elif os.environ.get("REGISTER_COUNT", "").isdigit():
        total = int(os.environ["REGISTER_COUNT"])
    if total is None or total <= 0:
        while True:
            try:
                total = int(input("\n请输入要注册的账号数量："))
                if total > 0:
                    break
            except ValueError:
                pass
            print("❌ 请输入大于0的整数")
    else:
        print(f"\n📋 本次注册数量：{total}（来自命令行/环境变量）")

    ok = fail = 0
    fails = []
    for i in range(1, total + 1):
        print(f"\n========== 第{i}/{total}个账号 ==========")
        info = gen_random_info()
        print(f"🎲 用户名：{info['username']}  密码：{info['password']}")
        try:
            r = single_register(info)
            uid = r.get('userId') if isinstance(r, dict) else None
            print(f"🎉 注册成功！userId={uid}")
            token = login_verify(info['username'], info['password'])
            if token:
                ok += 1
                save_account(info['username'], info['password'], uid)
                print(f"✅ 登录验证通过，已写入 {ACCOUNTS_FILE}")
            else:
                fail += 1
                fails.append(f"第{i}个：{info['username']} - 注册成功但登录失败")
                print(f"❌ 注册成功但登录验证失败")
        except Exception as e:
            fail += 1
            fails.append(f"第{i}个：{info['username']} - {str(e)}")
            print(f"❌ 失败：{str(e)}")

    print("\n===== 统计报告 =====")
    print(f"📊 总数：{total} | 成功(可登录)：{ok} | 失败：{fail}")
    if ok:
        avg = _total_attempts / max(1, ok)
        print(f"⏱  平均每个账号换图 {avg:.1f} 次")
        print(f"📁 可用账号已保存：{ACCOUNTS_FILE}")
    for f in fails:
        print("  -", f)
