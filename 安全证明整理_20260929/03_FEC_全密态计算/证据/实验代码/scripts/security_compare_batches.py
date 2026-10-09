"""两轮证据逐项对比 —— 复测是否重现首轮结论。

用法：
    python scripts/security_compare_batches.py \
        --baseline results/security_full_20260918 \
        --recheck  results/security_recheck_20260918 \
        --output   results/security_recheck_20260918/comparison.json

每个测试项提取若干"关键指标"（而不是整份 JSON 逐字节比），因为时间戳、
run_id、nonce、临时目录名每次必然不同，逐字节比只会得到"全部不一致"的废结论。
指标相同即判重现；不同则原样列出两轮的值，由人判断是环境变化还是回归。
"""
import argparse
import json
from pathlib import Path
import re


def load(path):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except Exception:
        return None


def dig(doc, *keys, default=None):
    cur = doc
    for k in keys:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return default
    return cur


def count_true(d):
    if isinstance(d, dict):
        vals = [v for v in d.values() if isinstance(v, bool)]
        return '%d/%d' % (sum(vals), len(vals)) if vals else None
    return None


# 每项：(基线目录名, 复测目录名, 指标提取函数)
def m_attest(p):
    d = load(p / 'controls.json') or {}
    tests = d.get('tests')
    if isinstance(tests, list) and tests:
        return {'负例通过': '%d/%d' % (sum(1 for t in tests if t.get('passed')), len(tests))}
    if 'passed' in d and 'total' in d:
        return {'负例通过': '%s/%s' % (d['passed'], d['total'])}
    return {}


def m_wire(p):
    d = load(p / 'analysis.json') or {}
    checks = d.get('checks')
    out = {}
    if isinstance(checks, list):
        out['检查项'] = '%d/%d' % (sum(1 for c in checks if c.get('passed')), len(checks))
    elif isinstance(checks, dict):
        out['检查项'] = count_true(checks)
    for k in ('passed', 'marker_visible', 'control_marker_visible'):
        if k in d:
            out[k] = d[k]
    return out


def m_pair(p):
    d = load(p / 'pair_result.json') or load(p / 'result.json') or {}
    tests = d.get('tests')
    return {'检查项': ('%d/%d' % (sum(1 for t in tests if t.get('passed')), len(tests))
                       if isinstance(tests, list) and tests else None),
            '后端请求增量': d.get('backend_request_delta')}


def m_dual(p):
    d = load(p / 'result.json') or {}
    rounds = d.get('rounds') or []
    same = [r.get('identical') if 'identical' in r else
            (r.get('plain_sha256') == r.get('cipher_sha256')) for r in rounds]
    return {'通过': d.get('passed'), '轮数': len(rounds),
            '逐轮输出相同': (all(same) if same else None)}


def m_simple(p):
    d = load(p / 'result.json') or {}
    # 各脚本用的键不统一：passed / pass / semantic_pass 都出现过
    for k in ('passed', 'pass'):
        if k in d:
            return {'通过': d[k]}
    return {}


def m_pass_semantic(p):
    """NPU 与 workspace 探针用 pass / semantic_pass。"""
    d = load(p / 'result.json') or {}
    out = {'通过': d.get('pass', d.get('passed'))}
    if 'semantic_pass' in d:
        out['语义校验'] = d['semantic_pass']
    if 'backend_request_count_unchanged' in d:
        out['后端请求未变'] = d['backend_request_count_unchanged']
    return out


def m_nofallback(p):
    d = load(p / 'result.json') or {}
    att = d.get('attempts') or d.get('variants') or []
    return {'通过': d.get('passed'), '降级尝试数': len(att) if isinstance(att, list) else None,
            '全部无效': (all(not a.get('changed_output', False) for a in att)
                         if isinstance(att, list) and att else None)}


def m_cdc(p):
    """首轮是临时脚本没有 result.json，因此统一从原始输出文本判，两轮可比。"""
    f = p / 'npu_security_capability.txt'
    if not f.exists():
        return {}
    t = f.read_text(encoding='utf-8', errors='replace')

    def state(key):
        m = re.search(r'### -t ' + re.escape(key) + r'\n(.*?)(?=\n### -t |\n####|\Z)', t, re.S)
        body = (m.group(1) if m else '').strip()
        if not body:
            return 'no-output'
        if 'does not support' in body:
            return 'unsupported'
        if 'cannot be executed on a VM or container' in body:
            return 'blocked-in-vm'
        return 'reported'

    ds = re.search(r'Device-share Status\s*:\s*(\S+)', t)
    km = 'Stop' if re.search(r'service running status\s*:\s*Stop', t) else (
        'Running' if 'service running status' in t else None)
    return {'work-mode': state('work-mode'), 'rootkey': state('rootkey'),
            'tls-cert': state('tls-cert'), 'key-manage': km,
            'device-share': ds.group(1) if ds else None}


def m_tdc_access(p):
    """统一从原始输出文本判，首轮（临时脚本，无 result.json）与复测可比。"""
    def read(name):
        f = p / name
        return f.read_text(encoding='utf-8', errors='replace') if f.exists() else ''
    host, cvm = read('host_side.txt'), read('cvm_side.txt')
    if not host and not cvm:
        return {}
    iommu = re.findall(r'组内设备数 (\d+)', host)
    denied = re.findall(r'(?:davinci0|devmm_svm|davinci_manager) exit=(\d+)', cvm)
    return {'宿主无设备节点': 'No such file' in host,
            '宿主BAR读0字节': bool(re.search(r'resource0 读取结果:.*0 bytes', host)),
            '两卡vfio-pci': host.count('vfio-pci') >= 2,
            'IOMMU每组1设备': (all(n == '1' for n in iommu) if iommu else None),
            'CVM非特权全被拒': (all(m != '0' for m in denied) if len(denied) >= 3 else None)}


def m_cancel(p):
    d = load(p / 'cancel_result.json') or load(p / 'result.json') or {}
    checks = d.get('checks')
    return {'通过': d.get('passed'),
            '检查项': count_true(checks) if isinstance(checks, dict) else (
                '%d/%d' % (sum(1 for c in checks if c.get('passed')), len(checks))
                if isinstance(checks, list) else None),
            '后端已停止': d.get('backend_cancel_proven'),
            '取消后解码批次': d.get('decode_batches_after_cancel')}


def m_npu(p):
    d = load(p / 'result.json') or {}
    cases = d.get('cases') or d.get('results') or []
    return {'通过': d.get('passed'),
            '算例': ('%d/%d' % (sum(1 for c in cases if c.get('passed', c.get('ok'))), len(cases))
                     if isinstance(cases, list) and cases else None)}


def m_devres(p):
    d = load(p / 'result.json') or {}
    rounds = d.get('rounds') or []
    return {'通过': d.get('passed'),
            '轮数': len(rounds),
            '均无残留': (all(not r.get('residue_found') for r in rounds) if rounds else None),
            '读路径有效': (all(r.get('read_path_valid') for r in rounds) if rounds else None)}


def m_fault(p):
    d = load(p / 'result.json') or {}
    return {'通过': d.get('passed'),
            '用例': ('%s/%s' % (d.get('pass_count'), (d.get('pass_count') or 0) + (d.get('fail_count') or 0))
                     if d.get('pass_count') is not None else None),
            '批次静默缺口重现': dig(d, 'findings', 'batch_path_silent_on_device_fault'),
            '随机源失效中止': dig(d, 'findings', 'csprng_failure_aborts')}


def m_memory(p):
    d = load(p / 'result.json') or {}
    return {'覆盖率': (round(d['guest_coverage_ratio'], 4)
                       if isinstance(d.get('guest_coverage_ratio'), (int, float)) else None),
            '读取成功': d.get('guest_read_succeeded'),
            '运行时标记命中': dig(d, 'guest_scan_hits', default=d.get('guest_marker_hits')),
            '通过': d.get('passed')}


def m_selfcheck(p):
    d = load(p / 'customer_selfcheck.json') or {}
    checks = d.get('checks') or d.get('items')
    return {'通过': d.get('passed'),
            '检查项': (count_true(checks) if isinstance(checks, dict) else
                       ('%d/%d' % (sum(1 for c in checks if c.get('passed')), len(checks))
                        if isinstance(checks, list) else None))}


def m_acceptance(p):
    for name in ('security_acceptance_raw.json', 'result.json', 'acceptance.json'):
        d = load(p / name)
        if d:
            tests = d.get('tests') or d.get('cases') or []
            if isinstance(tests, list) and tests:
                ok = sum(1 for t in tests if t.get('passed') or t.get('returncode') == 0)
                return {'项目': '%d/%d' % (ok, len(tests))}
            if 'passed' in d:
                return {'通过': d['passed']}
    return {}


ITEMS = [
    ('证明负例',          'attest_01',          'attest',      m_attest),
    ('8000 入口抓包',     'wire_gateway_01',    'wire_gw',     m_wire),
    ('8101 入口抓包',     'wire_sdk_01',        'wire_sdk',    m_wire),
    ('并发跨密钥隔离',    'pair_01',            'pair',        m_pair),
    ('明密文双入口',      'dual_entry_01',      'dual_entry',  m_dual),
    ('旁路残留',          'residue_01',         'residue',     m_simple),
    ('运行时不可降级',    'no_fallback_01',     'no_fallback', m_nofallback),
    ('CDC 平台能力',      'cdc01_platform',     'cdc',         m_cdc),
    ('非授权侧访问',      'tdc04_access',       'tdc_access',  m_tdc_access),
    # 取消传播的首轮证据在上线批次里，不在本批次目录下
    ('取消传播', '../security_cancel_deploy_20260918/cancel_live_02', 'cancel', m_cancel),
    ('NPU 设备算例',      'npu_01',             'npu',         m_pass_semantic),
    ('workspace 生命周期', 'workspace_01',      'workspace',   m_pass_semantic),
    ('设备内存残留',      'device_residue_02',  'dev_residue', m_devres),
    ('故障注入',          'fault_injection_02', 'fault',       m_fault),
    ('内存隔离全扫',      'tdc_memory_06_full', 'memory',      m_memory),
    ('客户自验',          'selfcheck_01',       'selfcheck',   m_selfcheck),
    ('加密入口验收',      'acceptance_02',      'acceptance',  m_acceptance),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--baseline', type=Path, required=True)
    ap.add_argument('--recheck', type=Path, required=True)
    ap.add_argument('--output', type=Path)
    args = ap.parse_args()

    report = {'baseline': str(args.baseline), 'recheck': str(args.recheck), 'items': []}
    width = 20
    print('%-*s %-28s %-28s %s' % (width, '测试项', '首轮', '复测', '结论'))
    print('-' * 104)
    for title, base_dir, re_dir, fn in ITEMS:
        bp = args.baseline / base_dir if base_dir else None
        rp = args.recheck / re_dir
        b = fn(bp) if bp and bp.exists() else None
        r = fn(rp) if rp.exists() else None
        if b is None and r is None:
            verdict = '两轮均无'
        elif r is None:
            verdict = '复测缺失'
        elif b is None:
            verdict = '仅复测有'
        else:
            keys = [k for k in r if r[k] is not None and k in b and b[k] is not None]
            verdict = '一致' if keys and all(b[k] == r[k] for k in keys) else (
                '有差异' if keys else '无可比指标')
        report['items'].append({'title': title, 'baseline': b, 'recheck': r, 'verdict': verdict})
        fmt = lambda d: ('-' if d is None else
                         ' '.join('%s=%s' % (k, v) for k, v in d.items() if v is not None)[:27])
        print('%-*s %-28s %-28s %s' % (width, title, fmt(b), fmt(r), verdict))

    same = sum(1 for i in report['items'] if i['verdict'] == '一致')
    diff = sum(1 for i in report['items'] if i['verdict'] == '有差异')
    report['counts'] = {'一致': same, '有差异': diff, '总数': len(report['items'])}
    print('-' * 104)
    print('一致 %d / 有差异 %d / 共 %d' % (same, diff, len(report['items'])))
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        print('已写入 ' + str(args.output))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
