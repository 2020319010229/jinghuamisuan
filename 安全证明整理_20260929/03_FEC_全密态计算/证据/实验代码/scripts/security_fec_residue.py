"""FEC side-channel residue: after a real encrypted request, does the plaintext leak into
logs, temporary files or crash dumps — on the CVM and on the untrusted host?

Sends one encrypted request whose prompt carries a unique marker, then searches both machines
for that marker. A planted control file proves the search itself works, so "not found" is not
just a broken grep. Read-only apart from the control file, which is removed afterwards.
"""
import argparse
import json
from pathlib import Path
import secrets
import shlex
import time

from security_remote import Remote

CVM_PATHS = '/var/log /tmp /data/otp_c35 /opt/cvm/data'
HOST_PATHS = '/var/log /tmp /root/client'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--output-dir', type=Path, required=True)
    ap.add_argument('--max-tokens', type=int, default=16)
    args = ap.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)

    marker = 'OTPRESIDUE' + secrets.token_hex(10)
    control = 'OTPCONTROL' + secrets.token_hex(10)
    report = {'started_ns': time.time_ns(), 'passed': False,
              'scope': 'one encrypted request; marker search across CVM and host logs, '
                       'temp files and crash dumps, with a planted positive control',
              'marker_prefix': marker[:14] + '…'}
    remote = None
    try:
        remote = Remote()

        def run(target, name, cmd, timeout=120):
            res = remote.run(target, cmd, timeout=timeout)
            report[name] = {'exit_code': res['exit_code'], 'stdout': res['stdout'][-2500:],
                            'stderr': res['stderr'][-500:]}
            return res['stdout'].strip()

        # positive control: a file that the search must find
        ctrl_file = '/tmp/otp-security-residue-control.txt'
        for target in ('cvm', 'host'):
            run(target, 'plant_control_' + target,
                'printf %s ' + shlex.quote(control) + ' > ' + ctrl_file + ' && echo planted')

        # a real encrypted request carrying the marker in its prompt
        prompt = 'residue check %s: reply with the word ok.' % marker
        started = time.monotonic()
        out = run('cvm', 'encrypted_request',
                  'cd /data/otp_c35 && python3 tee_client.py --url http://127.0.0.1:8000 '
                  '--prompt ' + shlex.quote(prompt) + ' --max-tokens ' + str(args.max_tokens),
                  timeout=1200)
        report['request_elapsed_ms'] = round((time.monotonic() - started) * 1000, 1)
        report['request_ok'] = '"choices"' in out or 'choices' in out
        time.sleep(3)

        def search(target, paths, label):
            # -I skips binaries; keep the walk bounded so this stays a quick check
            cmd = ('grep -rIl --binary-files=without-match -e ' + shlex.quote(marker)
                   + ' -e ' + shlex.quote(control) + ' ' + paths + ' 2>/dev/null | head -40; '
                   'echo "---DOCKER---"; ')
            if target == 'cvm':
                cmd += ('for c in otp-c35-cb cvm-server; do '
                        'n=$(docker logs --tail 5000 $c 2>&1 | grep -c ' + shlex.quote(marker) + ' || true); '
                        'echo "$c:$n"; done; ')
            cmd += ('echo "---DUMPS---"; cat /proc/sys/kernel/core_pattern 2>/dev/null; '
                    'ls -1 /var/lib/systemd/coredump 2>/dev/null | head -5; '
                    'ls -1 /var/crash 2>/dev/null | head -5')
            return run(target, label, cmd, timeout=300)

        cvm_out = search('cvm', CVM_PATHS, 'search_cvm')
        host_out = search('host', HOST_PATHS, 'search_host')

        def parse(out_text):
            files_part = out_text.split('---DOCKER---')[0]
            files = [f.strip() for f in files_part.splitlines() if f.strip()]
            marker_files = [f for f in files if f != '/tmp/otp-security-residue-control.txt']
            control_found = any(f == '/tmp/otp-security-residue-control.txt' for f in files)
            docker_counts = {}
            if '---DOCKER---' in out_text:
                mid = out_text.split('---DOCKER---')[1].split('---DUMPS---')[0]
                for line in mid.splitlines():
                    if ':' in line:
                        k, _, v = line.partition(':')
                        try:
                            docker_counts[k.strip()] = int(v.strip())
                        except ValueError:
                            pass
            return {'files_with_marker': marker_files, 'control_file_found': control_found,
                    'docker_log_marker_counts': docker_counts}

        report['cvm'] = parse(cvm_out)
        report['host'] = parse(host_out)
        report['cvm']['raw_tail'] = cvm_out[-600:]
        report['host']['raw_tail'] = host_out[-600:]

        controls_ok = report['cvm']['control_file_found'] and report['host']['control_file_found']
        no_files = not report['cvm']['files_with_marker'] and not report['host']['files_with_marker']
        no_docker = all(v == 0 for v in report['cvm']['docker_log_marker_counts'].values()) \
            if report['cvm']['docker_log_marker_counts'] else False
        report['search_controls_positive'] = controls_ok
        report['no_marker_in_files'] = no_files
        report['no_marker_in_container_logs'] = no_docker
        report['passed'] = bool(controls_ok and no_files and no_docker and report['request_ok'])
    except Exception as exc:
        report['error_type'] = type(exc).__name__
        report['error'] = str(exc)
    finally:
        if remote:
            for target in ('cvm', 'host'):
                try:
                    remote.run(target, 'rm -f /tmp/otp-security-residue-control.txt', timeout=30)
                except Exception:
                    pass
            remote.close()
        report['finished_ns'] = time.time_ns()
        with (args.output_dir / 'result.json').open('x', encoding='utf-8') as out_f:
            json.dump(report, out_f, ensure_ascii=False, indent=2)
    print(json.dumps({k: report.get(k) for k in
                      ('passed', 'error', 'search_controls_positive', 'no_marker_in_files',
                       'no_marker_in_container_logs', 'request_ok')}, ensure_ascii=False))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
