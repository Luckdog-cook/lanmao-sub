#!/usr/bin/env python3
"""iPoW.ai 自动注册 + 全网节点拉取（429 自动换号续传）。

**独立单文件**：不依赖 ipow_client.py 或 generate_configs.py，所有必要代码已内联。

用法
----
    python auto_register.py                      # 拉全部节点
    python auto_register.py --limit 5             # 只拉前 5 个
    python auto_register.py --wallets 3           # 最多用 3 个钱包
    python auto_register.py --interval 2.5        # 请求间隔
    python auto_register.py -v                    # 详细输出
"""

import argparse
import base64
import json
import os
import random
import re
import sys
import time

# ---------- 依赖检查 ----------
_missing = []
try:
    import requests
except ImportError:
    _missing.append('requests')
try:
    from eth_account import Account
except ImportError:
    _missing.append('eth-account')
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    _missing.append('cryptography')

if _missing:
    print(f'缺少依赖: {" ".join(_missing)}')
    print(f'运行: pip install {" ".join(_missing)}')
    sys.exit(1)

from eth_account.messages import encode_defunct

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
API_BASE = 'https://ipow.ai'
USER_AGENT = 'Dart/3.10 (dart:io)'
CLIENT_TYPE = 'android'
CLIENT_VERSION = '4.3.4'
CAPABILITY = 'vless-reality:no-flow'
DEFAULT_SNI = 'www.cloudflare.com'
DEFAULT_FINGERPRINT = 'chrome'
MERGED_NODES_FILE = 'all_nodes.json'
WALLETS_FILE = 'auto_wallets.json'

# ---------------------------------------------------------------------------
# 异常
# ---------------------------------------------------------------------------

class IpowError(RuntimeError):
    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code

class QuotaExhausted(IpowError):
    def __init__(self, detail=''):
        super().__init__(
            '配额已耗尽 (402)：试用到期或需要付费'
            + ('：' + detail if detail else ''),
            code='quota_exhausted')

class RateLimited(IpowError):
    def __init__(self, retry_after, detail=''):
        self.retry_after = max(int(retry_after or 0), 1)
        super().__init__('服务端限流 (429)，需等待 {} 秒{}'.format(
            self.retry_after, '：' + detail if detail else ''))

# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

def b64d(s):
    s = s.replace('-', '+').replace('_', '/')
    return base64.b64decode(s + '=' * (-len(s) % 4))


def country_code_from_node_id(node_id):
    m = re.search(r'-([a-z]{2})-\d+$', node_id or '')
    return m.group(1).upper() if m else None


def write_json(path, obj):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write('\n')
    os.replace(tmp, path)

# ---------------------------------------------------------------------------
# API 客户端
# ---------------------------------------------------------------------------

class IpowClient:
    def __init__(self, base=API_BASE, timeout=20, verbose=False):
        self.base = base.rstrip('/')
        self.timeout = timeout
        self.verbose = verbose
        self.http = requests.Session()
        self.http.headers.update({
            'User-Agent': USER_AGENT,
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        })

    def _request(self, method, path, body=None, token=None):
        headers = {'Authorization': 'Bearer ' + token} if token else {}
        url = self.base + path
        if self.verbose:
            shown = json.dumps(body, ensure_ascii=False)[:160] if body else ''
            print('  -> {} {} {}'.format(method, path, shown))
        r = self.http.request(method, url, json=body, headers=headers,
                              timeout=self.timeout)
        if self.verbose:
            print('  <- {} {}'.format(r.status_code, r.text[:160]))
        if r.status_code == 429:
            raw = r.headers.get('Retry-After') or r.headers.get('retry-after')
            try:
                retry_after = int(float(raw))
            except (TypeError, ValueError):
                retry_after = 30
            raise RateLimited(retry_after, r.text[:120])
        if r.status_code == 401:
            raise IpowError('JWT 已失效 (401)')
        if r.status_code == 402:
            raise QuotaExhausted(r.text[:160])
        if r.status_code >= 400:
            code = None
            try:
                code = (r.json().get('error') or {}).get('code')
            except ValueError:
                pass
            raise IpowError('HTTP {} {}: {}'.format(
                r.status_code, path, r.text[:300]), code=code)
        try:
            return r.json()
        except ValueError:
            raise IpowError('响应不是 JSON: ' + r.text[:200])

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
# 解密与配置生成（内联自 generate_configs.py + ipow_client.py）
# ---------------------------------------------------------------------------

def node_name(node):
    return "iPoW-{}-{}".format(node.get('country_code', 'XX'), node['node_id'])


def build_vless_url(node):
    name = node_name(node)
    fp = node.get('fingerprint') or DEFAULT_FINGERPRINT
    parts = [
        'encryption=none',
        'flow=',
        'security=reality',
        'sni={}'.format(node.get('sni') or DEFAULT_SNI),
        'fp={}'.format(fp),
        'pbk={}'.format(node['public_key']),
        'sid={}'.format(node['short_id']),
        'type=tcp',
    ]
    return 'vless://{}@{}:{}?{}#{}'.format(
        node['uuid'], node['server'], node['port'], '&'.join(parts), name)


def build_clash_yaml(nodes):
    lines = [
        '# Clash Meta / Mihomo Proxies Configuration',
        'proxies:',
    ]
    for n in nodes:
        lines.append("  - name: '{}'".format(node_name(n)))
        lines.append('    type: vless')
        lines.append('    server: {}'.format(n['server']))
        lines.append('    port: {}'.format(n['port']))
        lines.append('    uuid: {}'.format(n['uuid']))
        lines.append('    network: tcp')
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
        outbounds.append({
            'type': 'vless',
            'tag': node_name(n),
            'server': n['server'],
            'server_port': n['port'],
            'uuid': n['uuid'],
            'packet_encoding': 'xudp',
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


def write_configs(nodes, work_dir, quiet=False):
    os.makedirs(work_dir, exist_ok=True)
    nodes = [
        dict(n, vless_url=n.get('vless_url') or build_vless_url(n))
        for n in nodes
    ]
    paths = {
        'json': os.path.join(work_dir, MERGED_NODES_FILE),
        'vless': os.path.join(work_dir, 'all_nodes_vless.txt'),
        'clash': os.path.join(work_dir, 'clash_proxies.yaml'),
        'singbox': os.path.join(work_dir, 'singbox_outbounds.json'),
    }
    with open(paths['json'], 'w', encoding='utf-8', newline='\n') as f:
        f.write(json.dumps(nodes, indent=2, ensure_ascii=False) + '\n')
    with open(paths['vless'], 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(n['vless_url'] for n in nodes) + '\n')
    with open(paths['clash'], 'w', encoding='utf-8', newline='\n') as f:
        f.write(build_clash_yaml(nodes) + '\n')
    with open(paths['singbox'], 'w', encoding='utf-8', newline='\n') as f:
        f.write(json.dumps(build_singbox_json(nodes), indent=2,
                            ensure_ascii=False) + '\n')
    if not quiet:
        print('已写入 {} 个节点:'.format(len(nodes)))
        for k, p in paths.items():
            print('  {} -> {}'.format(k, p))
    return paths


def decrypt_profile(resp):
    ep = resp.get('encrypted_profile')
    if not ep:
        raise IpowError('响应里没有 encrypted_profile')
    keys = {k.get('key_id'): k.get('key')
            for k in (resp.get('profile_decryption_keys') or [])}
    key = keys.get(ep.get('key_id')) or resp.get('profile_decryption_key')
    if not key:
        raise IpowError('响应里没有可用的 profile 解密密钥')
    plaintext = AESGCM(b64d(key)).decrypt(
        b64d(ep['nonce']), b64d(ep['ciphertext']), None)
    return json.loads(plaintext)


def node_from_capability(resp):
    profile = decrypt_profile(resp)
    payload = (resp.get('signed_record') or {}).get('payload') or {}
    tls = profile.get('tls') or {}
    reality = tls.get('reality') or {}
    node_id = (resp.get('selected_node_id') or resp.get('node_id')
               or payload.get('node_id'))
    node = {
        'node_id': node_id,
        'country': resp.get('selected_country_name') or payload.get('country'),
        'country_code': (resp.get('selected_country_code')
                         or country_code_from_node_id(node_id)),
        'city': payload.get('city'),
        'server': profile.get('server'),
        'port': profile.get('server_port'),
        'uuid': profile.get('uuid'),
        'sni': tls.get('server_name'),
        'public_key': reality.get('public_key'),
        'short_id': reality.get('short_id'),
        'vless_url': None,
        'region': payload.get('region'),
        'latency_ms': payload.get('latency_ms'),
    }
    for field in ('node_id', 'server', 'port', 'uuid', 'public_key', 'short_id'):
        if not node.get(field):
            raise IpowError('解出的节点缺少字段 {}: {}'.format(field, node))
    node['vless_url'] = build_vless_url(node)
    return node
# ---------------------------------------------------------------------------
# 钱包生成
# ---------------------------------------------------------------------------

def generate_wallet():
    account = Account.create()
    pk = '0x' + account.key.hex()
    return pk, account.address


def random_device_id():
    return ''.join(random.choices('0123456789abcdef', k=16))


def random_device_name():
    brands = ['Samsung', 'Xiaomi', 'OnePlus', 'Pixel', 'Huawei', 'Oppo', 'Vivo']
    return '{} {}'.format(random.choice(brands), random.randint(1000, 9999))

# ---------------------------------------------------------------------------
# 登录（SIWE 注册）
# ---------------------------------------------------------------------------

def register_new_wallet(client, verbose=False):
    pk, address = generate_wallet()
    device_id = random_device_id()
    device_name = random_device_name()

    if verbose:
        print(f'  新钱包: {address}')
        print(f'  设备ID: {device_id}')
        print(f'  设备名: {device_name}')

    ch = client.challenge(address)
    message = ch.get('message') or ch.get('nonce')
    if not message:
        raise IpowError(f'challenge 缺少 message: {ch}')

    account = Account.from_key(pk)
    signed = account.sign_message(encode_defunct(text=message))
    signature = '0x' + bytes(signed.signature).hex()

    res = client.verify(address, signature, ch.get('nonce'),
                        device_id, device_name)

    sub = res.get('subscription') or {}
    state = {
        'private_key': pk,
        'address': address.lower(),
        'jwt': res.get('token'),
        'user_id': sub.get('user_id'),
        'subscription_token': sub.get('token'),
        'subscription_url': sub.get('url'),
        'plan_id': sub.get('plan_id'),
        'expires_at': sub.get('expires_at'),
        'device_id': device_id,
        'device_name': device_name,
    }

    if res.get('is_new_user'):
        if verbose:
            print('  ✅ 新账号已创建')
    else:
        if verbose:
            print('  ⚡ 已有钱包，复用登录')

    return state

# ---------------------------------------------------------------------------
# 从单个钱包拉取节点
# ---------------------------------------------------------------------------

def pull_with_wallet(client, state, session_id, device_id, args, remaining_ids):
    nodes = []
    pulled = []
    token = state['jwt']
    sub_token = state.get('subscription_token')

    batch = remaining_ids[:args.batch_size]
    total = len(batch)
    print(f'  逐个拉取 {total} 个节点...')

    for idx, (node_id, country) in enumerate(batch):
        if idx:
            time.sleep(args.interval)

        print(f'    [{idx+1}/{total}] {node_id} ...', end=' ', flush=True)

        try:
            resp = client.capability(
                token, session_id, country, sub_token, device_id,
                node_id=node_id)
        except RateLimited as exc:
            print(f'429 限流! 需等待 {exc.retry_after}s → 自动换号')
            return nodes, True, pulled
        except QuotaExhausted:
            print('402 配额耗尽!')
            return nodes, True, pulled
        except IpowError as exc:
            code = getattr(exc, 'code', None)
            if code in ('p2p_dht_capability_unavailable',
                        'p2p_lite_country_mismatch'):
                print('暂不可用')
            else:
                print(f'失败: {exc}')
            continue

        got = resp.get('selected_node_id') or resp.get('node_id')
        if got != node_id:
            print(f'未命中({got})')
            continue

        try:
            node = node_from_capability(resp)
        except IpowError as exc:
            print(f'解密失败: {exc}')
            continue

        nodes.append(node)
        pulled.append((node_id, country))
        print(f'{node["server"]} | {node.get("latency_ms", "-")}ms')

    return nodes, False, pulled

# ---------------------------------------------------------------------------
# 合并去重
# ---------------------------------------------------------------------------

def merge_nodes(existing, new_nodes):
    by_id = {n['node_id']: n for n in existing}
    added = 0
    for n in new_nodes:
        nid = n.get('node_id')
        if nid and nid not in by_id:
            added += 1
        if nid:
            by_id[nid] = n
    return list(by_id.values()), added

# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8', errors='replace')

    ap = argparse.ArgumentParser(
        prog='auto_register.py',
        description='iPoW.ai 自动注册 + 节点拉取（429 自动换钱包）')
    ap.add_argument('--interval', type=float, default=2.0,
                    help='每次请求间隔秒数，默认 %(default)s')
    ap.add_argument('--wallets', type=int, default=10,
                    help='最多使用多少个钱包，默认 %(default)s')
    ap.add_argument('--limit', type=int, default=None,
                    help='限制总拉取节点数（默认全部）')
    ap.add_argument('--batch-size', type=int, default=62,
                    help='每个钱包拉取的最大节点数，默认 %(default)s')
    ap.add_argument('--base-url', default=API_BASE,
                    help='接口地址，默认 %(default)s')
    ap.add_argument('-v', '--verbose', action='store_true',
                    help='详细输出')
    ap.add_argument('--quiet', action='store_true',
                    help='只输出最终结果')
    args = ap.parse_args(argv)

    if not args.quiet:
        print('=' * 60)
        print('iPoW.ai 自动注册 + 节点拉取')
        print('=' * 60)

    client = IpowClient(base=args.base_url, verbose=args.verbose)

    all_nodes = []
    seen_ids = set()

    # 从 API 拉取节点目录（不依赖本地文件）
    print('正在获取节点目录...')
    try:
        cat_body = client._request('GET', '/p2p-lite/v1/nodes?redacted=1')
    except IpowError:
        cat_body = client._request('GET', '/p2p-lite/v1/nodes')
    entries = cat_body.get('nodes') or cat_body.get('entries') or []
    if not entries:
        print('错误: 服务端未返回任何节点')
        return 1
    all_ids = [(e.get('id') or e.get('node_id'), e.get('country_code', 'AUTO'))
               for e in entries if e.get('id') or e.get('node_id')]
    target = args.limit or len(all_ids)
    remaining = all_ids[:target]

    print(f'目标: {target} 个节点')

    wallets_used = []

    while remaining:
        wallet_idx = len(wallets_used) + 1
        print(f'\n{"─" * 50}')
        print(f'钱包 #{wallet_idx} | 待拉 {len(remaining)} 个')

        # 1) 注册新钱包
        try:
            state = register_new_wallet(client, verbose=args.verbose)
            wallets_used.append({
                'address': state['address'],
                'user_id': state['user_id'],
                'plan_id': state['plan_id'],
            })
        except IpowError as exc:
            print(f'  ❌ 注册失败: {exc}')
            break
        except Exception as exc:
            print(f'  ❌ 注册异常: {exc}')
            break

        if len(wallets_used) > args.wallets:
            print(f'\n已达钱包上限 {args.wallets}')
            break

        # 2) 开启会话
        try:
            token = state['jwt']
            device_id = state['device_id']
            device_name = state['device_name']
            session = client.session_start(token, device_id, device_name)
            session_id = (session.get('session') or {}).get('id')
            if not session_id:
                print('  ❌ sessions/start 无 session_id')
                continue
            if not args.quiet:
                print(f'  会话: {session_id}')
        except IpowError as exc:
            print(f'  ❌ 开启会话失败: {exc}')
            continue

        # 3) 拉取节点
        try:
            nodes, rate_limited, pulled = pull_with_wallet(
                client, state, session_id, device_id, args, remaining)
        except Exception as exc:
            print(f'  ❌ 拉取异常: {exc}')
            continue

        # 4) 合并去重
        if nodes:
            all_nodes, added = merge_nodes(all_nodes, nodes)
            for n in nodes:
                nid = n.get('node_id')
                if nid:
                    seen_ids.add(nid)

            print(f'  ✅ 拉到 {len(nodes)} 个（总计 {len(all_nodes)}）')

            pulled_ids = {nid for nid, _ in pulled}
            remaining = [(nid, cc) for nid, cc in remaining
                         if nid not in seen_ids]

            write_json(os.path.join(BASE_DIR, MERGED_NODES_FILE), all_nodes)
        else:
            print('  ⚠️  本次未拉到节点')
            if rate_limited:
                continue
            else:
                break

        # 5) 429 时自动换钱包
        if rate_limited:
            print(f'  🔄 429 触发 → 注册新钱包继续拉取剩余 {len(remaining)} 个')
            time.sleep(1)
            continue

        if remaining:
            time.sleep(args.interval)

    # 保存钱包记录
    write_json(os.path.join(BASE_DIR, WALLETS_FILE), wallets_used)

    # 写出配置文件
    if all_nodes:
        print(f'\n{"=" * 60}')
        print(f'写出配置（{len(all_nodes)} 个节点）...')
        write_configs(all_nodes, BASE_DIR, quiet=args.quiet)
        # 固定订阅文件（一行一个 vless，方便 GitHub raw）
        ipow_path = os.path.join(BASE_DIR, 'ipow_nodes.txt')
        with open(ipow_path, 'w', encoding='utf-8', newline='\n') as f:
            f.write('\n'.join(
                n.get('vless_url') or build_vless_url(n) for n in all_nodes
            ) + '\n')
        if not args.quiet:
            print(f'  已生成订阅文件: ipow_nodes.txt （{len(all_nodes)} 条）')

    # 汇总
    print(f'\n{"=" * 60}')
    print('汇总:')
    print(f'  使用钱包数: {len(wallets_used)}')
    print(f'  总节点数:   {len(all_nodes)}')

    countries = {}
    for n in all_nodes:
        cc = n.get('country_code', '?')
        countries[cc] = countries.get(cc, 0) + 1
    if countries:
        print(f'  国家覆盖:   {len(countries)} 个')
        for cc in sorted(countries):
            print(f'    {cc}: {countries[cc]} 个节点')

    if wallets_used:
        print('\n已使用钱包:')
        for w in wallets_used:
            print(f'  {w["address"]} ({w["user_id"]})')

    print(f'\n{"=" * 60}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
