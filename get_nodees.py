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
OUT_DIR = ''          # GitHub Actions 直接写到仓库根目录
TIER_BY_FLAG = {1: 'pro', 0: 'free'}

UUID_RE = re.compile(
    r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
    r'[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
)


def log(msg=''):
    print(msg, file=sys.stderr, flush=True)


def fetch(retries=1):
    path = '/api/nodes/queryServerNodeList?applicationId=%s' % AID
    failures = []

    for base in ENDPOINTS:
        url = base.rstrip('/') + path
        doc, last_err = None, None
        for attempt in range(retries + 1):
            try:
                req = urllib.request.Request(url, headers=dict(HEADERS))
                with urllib.request.urlopen(req, timeout=20) as resp:
                    raw = resp.read()
                doc = json.loads(raw.decode('utf-8'))
                break
            except Exception as e:
                last_err = e
                if attempt < retries:
                    time.sleep(0.5 * (attempt + 1))

        if doc is None:
            reason = getattr(last_err, 'reason', last_err)
            log('  x %-30s %s' % (base, reason))
            failures.append('%s -> %s' % (base, reason))
            continue

        groups = doc.get('data') if isinstance(doc, dict) else doc
        if not isinstance(groups, list) or not groups:
            log('  x %-30s 返回内容异常' % base)
            failures.append('%s -> 无 data' % base)
            continue

        log('  + %-30s %d 组 / %d 条'
            % (base, len(groups), sum(len(g.get('children') or []) for g in groups)))
        return groups

    raise SystemExit('全部端点均失败:\n  ' + '\n  '.join(failures))


def unique_nodes(groups):
    nodes = {}
    for g in groups:
        tier = TIER_BY_FLAG.get(g.get('pro'), 'unknown')
        for n in g.get('children') or []:
            nid = n.get('id')
            if not nid:
                continue
            row = nodes.get(nid)
            if row is None:
                row = nodes[nid] = {
                    'id': nid,
                    'cc': g.get('country_code') or 'XX',
                    'city': n.get('city_code') or 'UNK',
                    'ip': n.get('ip'),
                    'port': n.get('port') or PORT,
                    'uuid': n.get('vless_uuid'),
                    'pbk': n.get('reality_public_key'),
                    'sid': n.get('reality_short_id'),
                    'sni': n.get('server_name') or SNI,
                    'tiers': [],
                }
            if tier not in row['tiers']:
                row['tiers'].append(tier)

    rows = list(nodes.values())
    for r in rows:
        r['tiers'] = '+'.join(sorted(r['tiers'], key=lambda t: (t != 'free', t)))
        r['from'] = {'free': 'free', 'pro': 'pro'}.get(r['tiers'], 'both')
    rows.sort(key=lambda r: (
        r['cc'],
        r['city'] or '',
        ip_key(r['ip'] or '0.0.0.0'),
    ))
    return rows


def ip_key(s):
    try:
        addr = ipaddress.ip_address(s)
    except (ValueError, TypeError):
        return (2, 0)
    return (0 if addr.version == 4 else 1, int(addr))


def norm_city(raw):
    if not raw:
        return 'UNK'
    s = unicodedata.normalize('NFKD', str(raw))
    s = s.encode('ascii', 'ignore').decode('ascii')
    s = re.sub(r'[^A-Za-z0-9]', '', s).upper()
    return s or 'UNK'


def name_of(row):
    return '%s-%s' % (row['cc'], norm_city(row['city']))


def build_links(rows):
    seq = collections.Counter()
    links = []
    for r in rows:
        key = name_of(r)
        seq[key] += 1
        label = 'YesVPN %s-%02d (%s)' % (key, seq[key], r['from'])
        query = '&'.join([
            'encryption=none',
            'security=reality',
            'sni=%s'   % quote(r['sni'], safe=''),
            'fp=%s'    % FP,
            'pbk=%s'   % quote(r['pbk'], safe=''),
            'sid=%s'   % quote(r['sid'], safe=''),
            'type=ws',
            'path=%s'  % quote(WS_PATH, safe='/'),
            'host=%s'  % quote(r['sni'], safe=''),
        ])
        links.append('vless://%s@%s:%d?%s#%s'
                     % (r['uuid'], r['ip'], r['port'], query, quote(label)))
    return links


def sanity_check(rows, links):
    problems = []
    if len(links) != len(rows):
        problems.append('链接数 %d != 节点数 %d' % (len(links), len(rows)))
    if len(set(links)) != len(links):
        problems.append('存在重复链接')

    for r in rows:
        nid = r.get('id', '?')

        for k in ('ip', 'uuid', 'pbk', 'sid', 'sni'):
            if not r.get(k):
                problems.append('节点 %s 缺少字段 %s' % (nid, k))

        uuid = str(r.get('uuid') or '')
        if uuid and not UUID_RE.match(uuid):
            problems.append('节点 %s uuid 格式非法: %r' % (nid, uuid))

        ip = str(r.get('ip') or '')
        if ip:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                problems.append('节点 %s ip 非法: %r' % (nid, ip))

        try:
            port = int(r.get('port'))
            if not (1 <= port <= 65535):
                raise ValueError
        except (TypeError, ValueError):
            problems.append('节点 %s port 非法: %r' % (nid, r.get('port')))

        pbk = str(r.get('pbk') or '')
        if pbk and len(pbk) < 20:
            problems.append('节点 %s pbk 长度异常: %d' % (nid, len(pbk)))

        sid = str(r.get('sid') or '')
        if sid and len(sid) > 32:
            problems.append('节点 %s sid 长度异常: %d' % (nid, len(sid)))

    return problems


def output_path():
    candidates = []
    if OUT_DIR:
        candidates.append(OUT_DIR)
    candidates.append(os.path.dirname(os.path.abspath(__file__)))

    for d in candidates:
        try:
            os.makedirs(d, exist_ok=True)
        except OSError:
            continue

        probe = os.path.join(d, '.vpn_write_probe')
        try:
            with open(probe, 'w', encoding='utf-8') as f:
                f.write('')
            os.remove(probe)
        except OSError as e:
            log('  ! %-40s 不可写 (%s)' % (d, e))
            continue

        return os.path.join(d, OUT_FILE)

    raise SystemExit('无可写输出目录: %s' % candidates)


def main():
    log('=== 获取节点 ===')
    groups = fetch()

    rows = unique_nodes(groups)
    links = build_links(rows)

    problems = sanity_check(rows, links)
    if problems:
        for p in problems:
            log('  !! %s' % p)
        raise SystemExit('自检未通过,已中止输出')

    sys.stdout.write('\n'.join(links) + '\n')
    sys.stdout.flush()

    path = output_path()
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(links) + '\n')

    log()
    log('=== 完成 ===')
    log('节点数   : %d' % len(rows))
    log('已写入   : %s' % path)
    log('按国家   : %s' % dict(collections.Counter(r['cc'] for r in rows)))
    log('档位     : 仅免费 %d / 仅付费 %d / 两档共有 %d'
        % (sum(1 for r in rows if r['tiers'] == 'free'),
           sum(1 for r in rows if r['tiers'] == 'pro'),
           sum(1 for r in rows if r['tiers'] == 'free+pro')))
    log('导入方式 : 复制上面的链接,或导入 %s' % os.path.basename(path))
    return 0


if __name__ == '__main__':
    sys.exit(main()) = ''
