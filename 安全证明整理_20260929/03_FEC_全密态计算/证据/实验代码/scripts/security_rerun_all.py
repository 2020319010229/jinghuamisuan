"""全量复测编排器 —— 一条命令重跑全部安全实验，产出可提交的过程包。

用法（在 otp_c35 目录下）：
    python scripts/security_rerun_all.py --output-dir results/security_recheck_YYYYMMDD
    python scripts/security_rerun_all.py --output-dir ... --only sdk,wire   # 只跑部分
    python scripts/security_rerun_all.py --output-dir ... --skip memory     # 跳过耗时项

设计约束（生产环境在线，必须遵守）：
  * 碰设备的实验（npu / workspace / device_residue / fault_injection）执行前
    检查后端是否空闲，非空闲则跳过而不是硬跑。
  * 任何一项失败不中断整体，记录后继续，最后汇总。
  * 每项写独立输出目录，不覆盖历史证据。
  * 参数与 2026-09-18 首轮完全一致，便于逐项对比。
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'scripts'
CVM_BASE = 'http://192.168.122.143:8101'
CLIENT_DIR = '/root/client'

# name, 说明, 对应计划书任务, 参数模板（{out} 会替换成该项输出目录）, 是否碰设备
PLAN = [
    ('env',        '环境与版本基线',        'G-02',
     ['security_environment_baseline.py', '--output', '{out}/env_baseline.json'], False),
    ('firmware',   '两卡固件与驱动版本',    'G-02',
     ['security_firmware_query.py', '--output', '{out}/firmware.json'], False),
    ('live',       '线上健康与运行身份',    'G-02/TDC-06',
     ['security_live_status.py', '--output', '{out}/live_status.json'], False),
    ('sdk',        'SDK 客户端与重放控制',  'G-03/FEC-03',
     ['security_run_sdk_probe.py', '--output-dir', '{out}', '--replay-controls', '--save-replay'], False),
    ('attest',     '证明负例（伪造材料）',  'TDC-02/FEC-01',
     ['security_run_attestation_controls.py', '--input', '{sdk}/sdk_result.json',
      '--output-dir', '{out}'], False),
    ('wire_gw',    '8000 网关入口抓包',     'G-04/FEC-04',
     ['security_run_wire_probe.py', '--output-dir', '{out}'], False),
    ('wire_sdk',   '8101 SDK 入口抓包',     'G-04/FEC-04',
     ['security_run_wire_probe.py', '--output-dir', '{out}', '--sdk'], False),
    ('pair',       '并发跨密钥隔离',        'FEC-04',
     ['security_run_sdk_pair.py', '--output-dir', '{out}'], False),
    ('dual_entry', '明密文双入口一致性',    'FEC-06',
     ['security_fec_dual_entry.py', '--output-dir', '{out}', '--rounds', '3', '--max-tokens', '24'], False),
    ('residue',    '旁路残留（日志/临时文件）', 'FEC-05',
     ['security_fec_residue.py', '--output-dir', '{out}', '--max-tokens', '16'], False),
    ('no_fallback', '运行时不可降级为明文', 'FEC-07',
     ['security_fec_no_fallback.py', '--output-dir', '{out}', '--max-tokens', '8'], False),
    ('cdc',        'CDC 平台能力核查',      'CDC-01/03',
     ['security_cdc_platform_check.py', '--output-dir', '{out}'], False),
    ('tdc_access', '非授权侧访问测试',      'TDC-04/07',
     ['security_tdc_access_check.py', '--output-dir', '{out}'], False),
    ('cancel',     '取消传播线上验收',      'FEC-08',
     ['security_run_sdk_cancel.py', '--output-dir', '{out}'], False),
    ('npu',        'NPU 设备接口合成算例',  'FEC-05',
     ['security_run_npu_extended.py', '--output-dir', '{out}', '--run-synthetic'], True),
    ('workspace',  'workspace 生命周期',    'FEC-02',
     ['security_run_workspace_probe.py', '--output-dir', '{out}'], True),
    ('dev_residue', '跨进程设备内存残留',   'TDC-05',
     ['security_run_device_residue.py', '--output-dir', '{out}', '--megabytes', '256', '--rounds', '2'], True),
    ('fault',      '故障注入与安全回退',    'FEC-08',
     ['security_run_fault_injection.py', '--output-dir', '{out}'], True),
    ('memory',     '宿主读 guest 内存全量扫描', 'TDC-03',
     ['security_tdc_memory_isolation.py', '--output-dir', '{out}',
      '--budget-bytes', '140000000000', '--hold-seconds', '3000'], False),
]

# 这两项不是本地脚本：selfcheck 在宿主以客户视角独立跑，acceptance 在 CVM 内跑
SPECIAL = ('selfcheck', 'acceptance')


def backend_idle(timeout=30):
    """复用 security_remote 查后端是否空闲；查不到时返回 None（谨慎起见按非空闲处理）。"""
    sys.path.insert(0, str(SCRIPTS))
    try:
        from security_remote import Remote
        r = Remote()
        try:
            res = r.run('cvm', "docker exec otp-c35-cb sh -c \"curl --noproxy '*' -fsS "
                               "--max-time 5 http://127.0.0.1:8020/metrics\"", timeout=timeout)
            m = json.loads(res['stdout'])
            return (m.get('active', 1) == 0 and m.get('queued', 1) == 0), m
        finally:
            r.close()
    except Exception as exc:
        return None, {'error': str(exc)}


def run_local(argv, cwd, timeout):
    env = dict(os.environ, PYTHONIOENCODING='utf-8')
    t0 = time.time()
    try:
        p = subprocess.run([sys.executable] + argv, cwd=str(cwd), env=env,
                           capture_output=True, text=True, encoding='utf-8',
                           errors='replace', timeout=timeout)
        return {'exit_code': p.returncode, 'stdout': (p.stdout or '')[-3000:],
                'stderr': (p.stderr or '')[-1500:], 'seconds': round(time.time() - t0, 1)}
    except subprocess.TimeoutExpired:
        return {'exit_code': -9, 'stdout': '', 'stderr': 'TIMEOUT',
                'seconds': round(time.time() - t0, 1)}


def fetch(remote, target, src, dst):
    """取回远端文件；远端不存在时 Remote.get 会写出 0 字节文件，必须当失败处理，
    否则包里会混进看起来像证据的空文件。"""
    try:
        remote.get(target, src, dst)
    except Exception:
        dst.unlink(missing_ok=True)
        return False
    if dst.exists() and dst.stat().st_size == 0:
        dst.unlink()
        return False
    return True


def run_selfcheck(out_dir, timeout=600):
    """把自验脚本传到宿主机，以客户视角独立执行（不走本项目采集链路）。"""
    sys.path.insert(0, str(SCRIPTS))
    from security_remote import Remote
    t0 = time.time()
    r = Remote()
    try:
        stage = '/tmp/otp-security-selfcheck-rerun'
        # 只建 stage，out 目录留给脚本自己建（它用 exist_ok=False）
        r.run('host', 'rm -rf ' + stage + ' && mkdir -p ' + stage, timeout=60)
        for name in ('security_customer_selfcheck.py', 'security_sdk_probe.py'):
            r.put('host', SCRIPTS / name, stage + '/' + name)
        # 不接管道：管道会把退出码变成 tail 的 0，掩盖脚本崩溃
        res = r.run('host', 'cd ' + stage + ' && timeout 420 python3 security_customer_selfcheck.py'
                    ' --base-url ' + CVM_BASE + ' --client-dir ' + CLIENT_DIR +
                    ' --output-dir ' + stage + '/out 2>&1', timeout=timeout)
        got = [name for name in ('customer_selfcheck.json', 'sdk_result.json',
                                 'selfcheck.json', 'test_dek_ownership.json')
               if fetch(r, 'host', stage + '/out/' + name, out_dir / name)]
        code = res['exit_code'] or (0 if got else 1)
        return {'exit_code': code, 'stdout': res['stdout'][-3000:],
                'stderr': res['stderr'][-1000:], 'seconds': round(time.time() - t0, 1),
                'fetched': got}
    finally:
        r.close()


def run_acceptance(out_dir, timeout=1200):
    """8000 加密入口 17 项验收，在 CVM 内跑；输出到独立目录，不覆盖历史记录。"""
    sys.path.insert(0, str(SCRIPTS))
    from security_remote import Remote
    t0 = time.time()
    r = Remote()
    try:
        stage = '/tmp/otp-security-acceptance-rerun'
        r.run('cvm', 'rm -rf ' + stage + ' && mkdir -p ' + stage + '/out', timeout=60)
        r.put('cvm', SCRIPTS / 'run_security_acceptance_20260828.py', stage + '/run_acceptance.py')
        # 同样不接管道，避免退出码被 tail 吞掉
        res = r.run('cvm', 'cd ' + stage + ' && OTP35_SECURITY_URL=http://127.0.0.1:8000'
                    ' OTP35_ROOT=/data/otp_c35 OTP35_SECURITY_OUT=' + stage + '/out'
                    ' timeout 900 python3 run_acceptance.py 2>&1', timeout=timeout)
        listing = r.run('cvm', 'ls ' + stage + '/out', timeout=60)['stdout'].split()
        got = [n for n in listing if fetch(r, 'cvm', stage + '/out/' + n, out_dir / n)]
        code = res['exit_code'] or (0 if got else 1)
        return {'exit_code': code, 'stdout': res['stdout'][-3000:],
                'stderr': res['stderr'][-1000:], 'seconds': round(time.time() - t0, 1),
                'fetched': got}
    finally:
        r.close()


def extract_verdict(out_dir):
    """从该项产出的 json 里抽一个粗判定，供汇总表显示。"""
    for name in ('result.json', 'cancel_result.json', 'analysis.json',
                 'customer_selfcheck.json', 'controls.json'):
        f = out_dir / name
        if not f.exists():
            continue
        try:
            doc = json.loads(f.read_text(encoding='utf-8'))
        except Exception:
            continue
        for key in ('passed', 'all_passed', 'ok'):
            if key in doc:
                return {'source': name, 'passed': bool(doc[key])}
        if isinstance(doc.get('checks'), dict):
            return {'source': name, 'passed': all(doc['checks'].values())}
    return {'source': None, 'passed': None}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--output-dir', type=Path, required=True)
    ap.add_argument('--only', default='', help='逗号分隔，只跑这些项')
    ap.add_argument('--skip', default='', help='逗号分隔，跳过这些项')
    ap.add_argument('--timeout', type=int, default=3600, help='单项超时秒数')
    ap.add_argument('--allow-busy', action='store_true',
                    help='后端不空闲时仍执行碰设备的实验（默认跳过）')
    args = ap.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    only = {s.strip() for s in args.only.split(',') if s.strip()}
    skip = {s.strip() for s in args.skip.split(',') if s.strip()}

    idle, metrics = backend_idle()
    # 补跑单项时必须并入既有汇总，否则会把整轮的执行记录覆盖掉
    summary_path = args.output_dir / 'rerun_summary.json'
    if summary_path.exists():
        try:
            summary = json.loads(summary_path.read_text(encoding='utf-8'))
            summary.setdefault('runs', []).append(
                {'started_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                 'only': args.only, 'skip': args.skip})
        except Exception:
            summary = None
    else:
        summary = None
    if summary is None:
        summary = {'started_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                   'batch_dir': str(args.output_dir),
                   'backend_idle_at_start': idle, 'backend_metrics_at_start': metrics,
                   'runs': [], 'items': []}
    summary.setdefault('items', [])
    print('后端空闲: %s  %s\n' % (idle, json.dumps(metrics, ensure_ascii=False)[:160]))

    order = [p[0] for p in PLAN] + list(SPECIAL)
    for name in order:
        if only and name not in only:
            continue
        if name in skip:
            continue
        spec = next((p for p in PLAN if p[0] == name), None)
        out_dir = args.output_dir / name
        if out_dir.exists():
            print('[跳过] %-12s 输出目录已存在' % name)
            continue

        if spec and spec[4] and not args.allow_busy:
            fresh_idle, m = backend_idle()
            if not fresh_idle:
                summary['items'].append({'name': name, 'status': 'skipped-busy',
                                         'reason': '后端非空闲，碰设备的实验已跳过', 'metrics': m})
                print('[跳过] %-12s 后端非空闲' % name)
                continue

        t0 = time.time()
        if name == 'selfcheck':
            out_dir.mkdir(parents=True, exist_ok=True)
            res = run_selfcheck(out_dir)
            desc, task, argv = '客户自验（宿主独立执行）', 'G-03/验收', ['<remote>']
        elif name == 'acceptance':
            out_dir.mkdir(parents=True, exist_ok=True)
            res = run_acceptance(out_dir)
            desc, task, argv = '加密入口篡改与重放 17 项', 'FEC-04', ['<remote>']
        else:
            _, desc, task, tpl, _ = spec
            # 用 --output 写单个文件的脚本不会自己建父目录；用 --output-dir 的
            # 脚本以 exist_ok=False 自建，这里绝不能抢先建
            if '--output' in tpl and '--output-dir' not in tpl:
                out_dir.mkdir(parents=True, exist_ok=True)
            argv = [str(SCRIPTS / tpl[0])] + [
                a.replace('{out}', str(out_dir)).replace('{sdk}', str(args.output_dir / 'sdk'))
                for a in tpl[1:]]
            res = run_local(argv, ROOT, args.timeout)

        # 抓包只产出 pcap，判定由分析器给出，必须紧接着跑
        analyze = None
        if name in ('wire_gw', 'wire_sdk') and res['exit_code'] == 0:
            argv_a = [str(SCRIPTS / 'security_analyze_wire.py'), str(out_dir)]
            if name == 'wire_sdk':
                argv_a.append('--sdk')
            ares = run_local(argv_a, ROOT, 900)
            analyze = {'argv': argv_a, 'exit_code': ares['exit_code'],
                       'seconds': ares['seconds'], 'stdout_tail': ares['stdout'][-600:]}
            if ares['exit_code'] != 0:
                res['exit_code'] = ares['exit_code']

        verdict = extract_verdict(out_dir)
        item = {'name': name, 'desc': desc, 'task': task, 'analyze': analyze,
                'argv': [str(a) for a in argv],
                'exit_code': res['exit_code'], 'seconds': res['seconds'],
                'verdict': verdict,
                'stdout_tail': res['stdout'][-800:], 'stderr_tail': res['stderr'][-500:]}
        item['status'] = ('ok' if res['exit_code'] == 0 else 'failed')
        # 同名项重跑时替换旧记录，不并列堆积
        summary['items'] = [i for i in summary['items'] if i.get('name') != name]
        summary['items'].append(item)
        print('[%s] %-12s %6.1fs  exit=%s  verdict=%s' %
              (item['status'], name, res['seconds'], res['exit_code'], verdict.get('passed')))
        with (args.output_dir / 'rerun_summary.json').open('w', encoding='utf-8') as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)

    idle_end, metrics_end = backend_idle()
    summary['backend_idle_at_end'] = idle_end
    summary['backend_metrics_at_end'] = metrics_end
    summary['finished_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    ok = sum(1 for i in summary['items'] if i.get('status') == 'ok')
    summary['counts'] = {'ok': ok, 'total': len(summary['items']),
                         'failed': sum(1 for i in summary['items'] if i.get('status') == 'failed'),
                         'skipped': sum(1 for i in summary['items']
                                        if i.get('status') == 'skipped-busy')}
    with (args.output_dir / 'rerun_summary.json').open('w', encoding='utf-8') as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print('\n汇总: ' + json.dumps(summary['counts'], ensure_ascii=False))
    return 0 if summary['counts']['failed'] == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
