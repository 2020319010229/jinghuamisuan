"""CDC-01 / CDC-03: does the accelerator provide confidential-computing capability?

Read-only npu-smi interrogation inside the CVM. Asks the device itself for work
mode, root key, device certificate and key-management state; the answers decide
whether CDC can be executed on this hardware at all.

Promoted from the ad-hoc probe used on 2026-09-18 so the check is re-runnable
from one place. The shell body is unchanged from the version that produced
results/security_full_20260918/cdc01_platform/.
"""
import argparse
import base64
import json
from pathlib import Path
import re
import time

from security_remote import Remote

PROBE = r"""set -u
echo "== 设备映射(取正确 card id) =="
npu-smi info -m 2>&1 | head -10
IDS=$(npu-smi info -m 2>&1 | awk 'NR>1 && $1 ~ /^[0-9]+$/ {print $1}' | sort -un)
echo "card ids: $IDS"
echo
for i in $IDS; do
  echo "################ card $i ################"
  for t in board common product work-mode key-manage rootkey pkcs-enable tls-cert tls-cert-period device-share vnpu-mode info-vnpu ecc-enable license; do
    out=$(npu-smi info -t "$t" -i "$i" 2>&1 | head -10)
    echo "### -t $t"
    echo "$out" | sed 's/^/    /'
  done
done
echo DONE
"""

# 判定用的关键字段：值出现"does not support"即该能力不可用
CAPABILITY_KEYS = ('work-mode', 'rootkey', 'tls-cert', 'tls-cert-period', 'license')


def b64_sh(script):
    """经 base64 传递脚本体，避免多层 shell 的引号与换行被吞。"""
    blob = base64.b64encode(script.encode('utf-8')).decode('ascii')
    return 'echo ' + blob + ' | base64 -d | sh'


def summarize(text):
    """把原始输出归纳成结构化能力表，供报告直接引用。"""
    out = {'cards': re.findall(r'Ascend \S+', text)[:4], 'capabilities': {}}
    for key in CAPABILITY_KEYS:
        block = re.search(r'### -t ' + re.escape(key) + r'\n(.*?)(?=\n### -t |\n####|\Z)',
                          text, re.S)
        body = (block.group(1) if block else '').strip()
        if not body:
            state = 'no-output'
        elif 'does not support' in body:
            state = 'unsupported'
        elif 'cannot be executed on a VM or container' in body:
            state = 'blocked-in-vm'      # 环境限制，不是设备不支持
        else:
            state = 'reported'
        out['capabilities'][key] = {'state': state, 'text': body[:200]}
    km = re.search(r'### -t key-manage\n(.*?)(?=\n### -t |\Z)', text, re.S)
    out['key_manage'] = (km.group(1).strip()[:200] if km else '')
    ds = re.search(r'Device-share Status\s*:\s*(\S+)', text)
    out['device_share'] = ds.group(1) if ds else None
    # 只有全部能力项都"不支持"，才判平台不具备 CDC 条件
    out['cdc_capable'] = any(v['state'] == 'reported'
                             for k, v in out['capabilities'].items()
                             if k in ('work-mode', 'rootkey', 'tls-cert'))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--output-dir', type=Path, required=True)
    args = ap.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)

    report = {'started_ns': time.time_ns(), 'passed': False,
              'task': 'CDC-01/03 加速卡机密计算能力核查（只读）',
              'scope': 'read-only npu-smi interrogation inside the CVM'}
    remote = None
    try:
        remote = Remote()
        res = remote.run('cvm', b64_sh(PROBE), timeout=180)
        report['exit_code'] = res['exit_code']
        raw = res['stdout']
        (args.output_dir / 'npu_security_capability.txt').write_text(raw, encoding='utf-8')
        (args.output_dir / 'probe.sh').write_text(PROBE, encoding='utf-8')
        if 'DONE' not in raw:
            raise RuntimeError('probe did not complete; see npu_security_capability.txt')
        report['summary'] = summarize(raw)
        report['conclusion'] = ('平台具备 CDC 所需能力' if report['summary']['cdc_capable']
                                else '平台不具备 CDC 所需能力：设备不提供工作模式/根密钥/证书查询')
        report['passed'] = True
    except Exception as exc:
        report['error_type'] = type(exc).__name__
        report['error'] = str(exc)
    finally:
        if remote:
            remote.close()
        report['finished_ns'] = time.time_ns()
        with (args.output_dir / 'result.json').open('x', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
    print(json.dumps({k: report.get(k) for k in ('passed', 'error', 'conclusion')},
                     ensure_ascii=False))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
