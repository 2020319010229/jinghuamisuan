#!/usr/bin/env python3
"""Remote baseline and isolated CPU test; never deploys or restarts services."""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import sys
import time

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'benchmark' / 'three_way_controlled_rerun'))
from run_controlled_three_way_remote import OuterHost, cvm_shell

CHECKS = {
    'system': 'uname -srmo; cat /etc/os-release; date -u +%FT%TZ',
    'devices': "ls -l /dev/davinci* /dev/vfio /dev/tsi /dev/tdx_guest /dev/sev-guest 2>/dev/null; command -v npu-smi; command -v nvidia-smi; true",
    'accelerator': 'if command -v npu-smi >/dev/null; then timeout 15 npu-smi info; elif command -v nvidia-smi >/dev/null; then timeout 15 nvidia-smi; else printf unavailable; fi',
    'containers': "if command -v docker >/dev/null; then timeout 10 docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'; else printf unavailable; fi",
    'listeners': "ss -lnt | head -60",
    'process_names': "ps -eo comm | sort | uniq -c | sort -nr | head -50",
    'source_identity': "for f in /data/otp_c35/tee_crypto.py /data/otp_c35/otp_rng.h /data/otp_c35/kunpeng_gateway.py; do if test -f \"$f\"; then sha256sum \"$f\"; fi; done; if test -d /data/otp_c35/.git; then git -C /data/otp_c35 rev-parse HEAD; fi; true",
    'health': "for p in 8000 8101 8030; do printf '\nport=%s\n' \"$p\"; curl --noproxy '*' -sS --max-time 3 -w '\nhttp_status=%{http_code}\n' \"http://127.0.0.1:$p/healthz\"; done; true",
}

FOLLOWUP = {
    'deployment_identity': "docker inspect --format '{{.Name}} image={{.Image}} network={{.HostConfig.NetworkMode}} {{range .Mounts}}mount={{.Source}}:{{.Destination}} {{end}}' otp-c35-cb cvm-server; for f in /usr/local/Ascend/driver/version.info /usr/local/Ascend/firmware/version.info; do if test -f \"$f\"; then cat \"$f\"; fi; done",
    'model_and_tools': "for f in /data/Qwen3.5-35B-A3B-w8a8-mtp/config.json /data/otp_c35/test_otp_security.c; do if test -f \"$f\"; then sha256sum \"$f\"; fi; done; for t in cc gcc tcpdump tshark; do command -v \"$t\" || true; done; docker exec otp-c35-cb sh -c 'command -v cc; command -v gcc; command -v tcpdump'",
    'api_metadata': "for u in http://127.0.0.1:8000/v1/tee/info http://127.0.0.1:8000/v1/tee/public-key; do curl --noproxy '*' -sS --max-time 3 -w '\nhttp_status=%{http_code}\n' \"$u\"; done",
    'rng_cpu_test': "set -eu; test -f /data/otp_c35/test_otp_security.c; test -f /data/otp_c35/otp_rng.h; command -v cc; experiment_dir=$(mktemp -d /tmp/otp-security-20260916.XXXXXX); printf 'experiment_dir=%s\\n' \"$experiment_dir\"; cp /data/otp_c35/test_otp_security.c /data/otp_c35/otp_rng.h \"$experiment_dir/\"; sha256sum \"$experiment_dir/test_otp_security.c\" \"$experiment_dir/otp_rng.h\"; cc --version | head -1; cc -O2 -Wall -Wextra -std=c11 \"$experiment_dir/test_otp_security.c\" -lm -o \"$experiment_dir/test_otp_security\"; timeout 15 \"$experiment_dir/test_otp_security\"",
}

CAPABILITIES = {
    'clock_1': "python3 -c 'import time; print(time.time_ns())'",
    'clock_2': "python3 -c 'import time; print(time.time_ns())'",
    'clock_3': "python3 -c 'import time; print(time.time_ns())'",
    'capture_tools': "for t in python3 tcpdump tshark dumpcap chronyc timedatectl; do command -v \"$t\" || true; done; timedatectl show -p NTPSynchronized -p NTP 2>/dev/null; python3 -c 'import socket; s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)); s.close(); print(\"AF_PACKET_available\")'",
    'pci_mapping': "if command -v lspci >/dev/null; then lspci -nnk; fi; for g in /sys/kernel/iommu_groups/83 /sys/kernel/iommu_groups/84; do if test -d \"$g/devices\"; then ls -l \"$g/devices\"; fi; done; true",
    'attestation_tools': "find /usr/local/bin /usr/bin /root /opt -maxdepth 4 -type f \\( -iname '*attest*' -o -iname '*virtcca*' -o -iname '*verifier*' \\) 2>/dev/null | head -60; true",
    'runtime_files': "if test -d /data/otp_c35; then ls -l /data/otp_c35/serve35_cb /data/otp_c35/tee_gateway.py /data/otp_c35/kunpeng_tee_gateway.py 2>/dev/null; sha256sum /data/otp_c35/serve35_cb 2>/dev/null; fi; if command -v docker >/dev/null; then docker exec cvm-server sh -c 'ls /opt/cvm; ls /app 2>/dev/null' 2>/dev/null; fi; true",
}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--phase', choices=('baseline', 'followup', 'capabilities'), default='baseline')
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    # Reserve exclusively before remote work; never replace an earlier run.
    with args.output.open('x', encoding='utf-8') as evidence:
        result = {
            'started_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
            'scope': ('read-only host/CVM operational baseline, not attestation verification'
                      if args.phase != 'followup' else
                      'deployment metadata plus CPU RNG test compiled in new remote temporary directory; not attestation verification'),
            'connection_limit': 'Existing connector does not authenticate previously unknown SSH host keys; remote identity is not cryptographically established by this run.',
            'collector_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'phase': args.phase,
            'checks': [],
        }
        host = OuterHost()
        try:
            try:
                host.run('true', timeout=30, retries=0)
                result['host_connected'] = True
            except Exception as exc:
                result['host_connected'] = False
                # Avoid logging credentials or command strings from connector errors.
                result['connection_error_type'] = type(exc).__name__
                print('Host connection failed; no remote tests executed.', flush=True)
            if result['host_connected']:
                for target in (('cvm',) if args.phase == 'followup' else ('host', 'cvm')):
                    commands = {'baseline': CHECKS, 'followup': FOLLOWUP, 'capabilities': CAPABILITIES}[args.phase]
                    for name, command in commands.items():
                        row = {'target': target, 'check': name, 'utc': dt.datetime.now(dt.timezone.utc).isoformat()}
                        try:
                            # Preserve failed command output and its exit code without
                            # allowing the connector to discard it or expose secrets.
                            wrapped = '( ' + command + ' ); check_rc=$?; printf "\\nCHECK_EXIT_CODE=%s\\n" "$check_rc"'
                            actual = wrapped if target == 'host' else 'timeout 35 ' + cvm_shell(wrapped)
                            row['local_before_ns'] = time.time_ns()
                            out, err = host.run(actual, timeout=45, retries=0)
                            row['local_after_ns'] = time.time_ns()
                            row.update(collected=True, stdout=out, stderr=err)
                            if name.startswith('clock_'):
                                remote_ns = int(out.strip().splitlines()[0])
                                row['remote_minus_local_bounds_ms'] = [(remote_ns-row['local_after_ns'])/1e6, (remote_ns-row['local_before_ns'])/1e6]
                        except Exception as exc:
                            row.update(collected=False, error_type=type(exc).__name__)
                        result['checks'].append(row)
                        print(target, name, 'collected' if row['collected'] else 'unavailable', flush=True)
        finally:
            host.close()
            result['finished_utc'] = dt.datetime.now(dt.timezone.utc).isoformat()
            json.dump(result, evidence, ensure_ascii=False, indent=2)
            evidence.write('\n')
        print(str(args.output), flush=True)

if __name__ == '__main__':
    main()
