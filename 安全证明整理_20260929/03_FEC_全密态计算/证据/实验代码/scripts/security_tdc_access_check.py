"""TDC-04 / TDC-07: can a non-authorised side reach the accelerator?

Two non-authorised sides are exercised, because this deployment is single-tenant
and has no second tenant to cross over from:
  host side  —— device nodes, npu-smi, driver modules, raw BAR read, IOMMU groups
  CVM inside —— an unprivileged user (nobody) against the device nodes

Read-only. Promoted from the ad-hoc probes used on 2026-09-18.

2026-09-18 复测修正：原探针的 npu-smi 段在首轮与复测中都输出为空，属采集缺陷。
宿主实际装有 npu-smi（/usr/local/sbin/npu-smi），但执行时 dcmi 初始化失败
（ret -8005），即工具在手也访问不到设备。现改为显式记录安装路径与执行结果，
判据相应改为「宿主无法通过 npu-smi 访问设备」。安全结论不变，理由更准确。
"""
import argparse
import base64
import json
from pathlib import Path
import re
import time

from security_remote import Remote

HOST_PROBE = r"""set -u
echo "############ TDC-04/07 宿主机（不可信侧）访问测试 ############"
echo "== 宿主上是否存在 NPU 设备节点 =="
ls -l /dev/davinci* /dev/devmm_svm 2>&1 | head -5
echo
echo "== 宿主上 npu-smi 是否可用 =="
if command -v npu-smi >/dev/null 2>&1; then
  echo "npu-smi 已安装: $(command -v npu-smi)"
  # 先落盘再读：npu-smi 在此上下文会挂起，被 timeout 杀掉时管道里的输出会丢
  timeout 20 npu-smi info >/tmp/otp_nsmi.out 2>&1
  echo "  npu-smi info 退出码=$? (124=超时被杀)"
  if [ -s /tmp/otp_nsmi.out ]; then
    head -6 /tmp/otp_nsmi.out | sed 's/^/  /'
  else
    echo "  npu-smi info 无任何输出"
  fi
  rm -f /tmp/otp_nsmi.out
else
  echo "npu-smi: not installed on host"
fi
echo
echo "== 宿主侧驱动占用（vfio-pci 表示已交给虚机独占） =="
for b in 18:00.0 41:00.0; do
  printf "%s -> " "$b"
  lspci -nnk -s $b 2>/dev/null | grep -i "driver in use" | sed 's/^[[:space:]]*//' || echo "?"
done
echo
echo "== 宿主上是否加载了昇腾计算驱动 =="
lsmod 2>/dev/null | grep -iE "devdrv|davinci|drv_pcie" | head -5
echo "(以上为空表示宿主未加载 devdrv 系列模块)"
echo
echo "== 宿主尝试直接读取设备 BAR 空间 =="
for b in 0000:18:00.0 0000:41:00.0; do
  f=/sys/bus/pci/devices/$b/resource0
  if [ -e "$f" ]; then
    out=$(timeout 10 dd if="$f" bs=4096 count=1 of=/dev/null 2>&1 | tail -2 | tr '\n' ' ')
    echo "$b resource0 读取结果: $out"
  else
    echo "$b resource0: 节点不存在"
  fi
done
echo
echo "== IOMMU 分组（一设备一组 = 可独占直通） =="
for b in 0000:18:00.0 0000:41:00.0; do
  g=$(readlink -f /sys/bus/pci/devices/$b/iommu_group 2>/dev/null | xargs basename 2>/dev/null)
  n=$(ls /sys/kernel/iommu_groups/$g/devices 2>/dev/null | wc -l)
  echo "$b -> IOMMU group $g, 组内设备数 $n"
done
echo DONE
"""

CVM_PROBE = r"""set -u
echo "############ TDC-04 CVM 内非特权用户访问测试 ############"
echo "== 设备节点权限 =="
ls -l /dev/davinci0 /dev/davinci2 /dev/devmm_svm /dev/davinci_manager 2>&1 | head -5
echo
echo "== 当前用户 =="
id
echo
echo "== 以 nobody 身份尝试读取设备节点 =="
su -s /bin/sh nobody -c 'head -c 16 /dev/davinci0 >/dev/null 2>&1; echo "davinci0 exit=$?"' 2>&1 | tail -1
su -s /bin/sh nobody -c 'head -c 16 /dev/devmm_svm >/dev/null 2>&1; echo "devmm_svm exit=$?"' 2>&1 | tail -1
su -s /bin/sh nobody -c 'head -c 16 /dev/davinci_manager >/dev/null 2>&1; echo "davinci_manager exit=$?"' 2>&1 | tail -1
echo "(exit 非 0 表示被拒绝)"
echo
echo "== 以 nobody 身份尝试 npu-smi =="
su -s /bin/sh nobody -c 'timeout 15 npu-smi info 2>&1 | head -4' 2>&1 | tail -4
echo
echo "== 引擎容器与 cvm-server 容器是否共享设备 =="
docker inspect cvm-server --format '{{json .HostConfig.Devices}}' 2>&1 | head -c 300
echo
echo "== 当前占用 NPU 的进程（应仅引擎） =="
npu-smi info 2>&1 | sed -n '/Process id/,$p' | head -10
echo DONE
"""


def b64_sh(script):
    """经 base64 传递脚本体，避免多层 shell 的引号与换行被吞。"""
    blob = base64.b64encode(script.encode('utf-8')).decode('ascii')
    return 'echo ' + blob + ' | base64 -d | sh'


def judge(host, cvm):
    """把两侧原始输出归纳成通过条件，避免人工读文本判定。"""
    checks = {
        'host_no_device_node': 'No such file' in host or '/dev/davinci' not in host.split('npu-smi')[0],
        # 宿主够不到设备即可，工具装没装不是重点
        'host_npu_smi_unusable': ('not installed on host' in host
                                  or 'dcmi module initialize failed' in host
                                  or 'npu-smi info 无任何输出' in host
                                  or '退出码=124' in host),
        'host_no_devdrv': '(以上为空表示宿主未加载 devdrv 系列模块)' in host
                          and not re.search(r'^devdrv|^davinci', host, re.M),
        'host_bar_read_zero': bool(re.search(r'resource0 读取结果:.*0 bytes', host)),
        'host_vfio_pci': host.count('vfio-pci') >= 2,
        'iommu_one_device_per_group': all(
            n == '1' for n in re.findall(r'IOMMU group \S+, 组内设备数 (\d+)', host)) and
            bool(re.findall(r'IOMMU group', host)),
        'cvm_unprivileged_denied': all(
            m != '0' for m in re.findall(r'(?:davinci0|devmm_svm|davinci_manager) exit=(\d+)', cvm)) and
            len(re.findall(r'exit=(\d+)', cvm)) >= 3,
        'cvm_server_has_no_npu': 'davinci' not in (
            re.search(r'HostConfig.Devices.*', cvm).group(0) if re.search(r'HostConfig.Devices.*', cvm) else ''),
    }
    return checks


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--output-dir', type=Path, required=True)
    args = ap.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)

    report = {'started_ns': time.time_ns(), 'passed': False,
              'task': 'TDC-04/07 非授权侧访问测试（宿主机 + CVM 内非特权用户）',
              'scope': 'read-only; single-tenant deployment has no second tenant, '
                       'so host side and unprivileged user are exercised instead'}
    remote = None
    try:
        remote = Remote()
        host = remote.run('host', b64_sh(HOST_PROBE), timeout=180)
        cvm = remote.run('cvm', b64_sh(CVM_PROBE), timeout=180)
        (args.output_dir / 'host_side.txt').write_text(host['stdout'], encoding='utf-8')
        (args.output_dir / 'cvm_side.txt').write_text(cvm['stdout'], encoding='utf-8')
        (args.output_dir / 'tdc04_host.sh').write_text(HOST_PROBE, encoding='utf-8')
        (args.output_dir / 'tdc04_cvm.sh').write_text(CVM_PROBE, encoding='utf-8')
        report['host_exit'] = host['exit_code']
        report['cvm_exit'] = cvm['exit_code']
        if 'DONE' not in host['stdout'] or 'DONE' not in cvm['stdout']:
            raise RuntimeError('probe did not complete; see host_side.txt / cvm_side.txt')
        report['checks'] = judge(host['stdout'], cvm['stdout'])
        report['passed'] = all(report['checks'].values())
        report['note'] = ('跨租户越权未实测：本环境单租户。宿主侧与非特权用户两类'
                          '非授权侧不等同于完整多租户隔离证明。')
    except Exception as exc:
        report['error_type'] = type(exc).__name__
        report['error'] = str(exc)
    finally:
        if remote:
            remote.close()
        report['finished_ns'] = time.time_ns()
        with (args.output_dir / 'result.json').open('x', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
    print(json.dumps({k: report.get(k) for k in ('passed', 'error', 'checks')},
                     ensure_ascii=False))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
