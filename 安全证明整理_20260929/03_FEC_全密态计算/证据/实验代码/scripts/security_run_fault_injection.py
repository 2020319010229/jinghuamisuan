"""FEC-08 fault injection: abort on error, or silent fallback?

Builds an independent test binary from a COPY of the engine sources inside the
container and exercises the密态 linear path under six fault conditions. The
production engine is never touched and no kernel is launched with an invalid
pointer, because the NPUs are shared with the live service.

Cases 4/5 simulate an accelerator that returns wrong results without reporting
an error: one output channel of the DEVICE weight is flipped while the trusted
host copy stays intact, then restored.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import time

from security_remote import Remote

CANN = '/usr/local/Ascend/cann-9.1.0/aarch64-linux'
ASCENDC = '/data/ascendc_grouped_v1/build'  # test_q8 与线上 serve35_cb 实际链接的版本
CONTAINER = 'otp-c35-cb'
SRC = '/data/otp_c35'
MODEL = '/data/Qwen3.5-35B-A3B-w8a8-mtp'

CFLAGS = ('-O3 -march=armv8.6-a+sve+i8mm+bf16 -std=c++17 -Wall -Wno-unused-function '
          '-Wno-deprecated-declarations -pthread -fopenmp')
LIBS = ('-lascendcl -lnnopbase -lopapi -L' + ASCENDC + ' -lbdszblind '
        '-Wl,-rpath,' + ASCENDC + ' -lm')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--output-dir', type=Path, required=True)
    args = ap.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)

    here = Path(__file__).parent
    probe = here / 'security_fault_injection.c'
    shim = here / 'security_fault_getrandom.c'

    report = {
        'started_ns': time.time_ns(),
        'passed': False,
        'task': 'FEC-08 异常处理与安全回退（故障注入）',
        'scope': 'independent process, engine sources copied out of the live tree; '
                 'production engine untouched; device weight corruption is reverted',
        'sources': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in (probe, shim)},
        'steps': [],
    }
    remote = None
    try:
        remote = Remote()

        def run(name, cmd, timeout=120, check=True):
            res = remote.run('cvm', cmd, timeout=timeout)
            report['steps'].append({'name': name, 'exit_code': res['exit_code'],
                                    'stdout': res['stdout'][-2000:],
                                    'stderr': res['stderr'][-2000:]})
            if check and res['exit_code']:
                raise RuntimeError(name + ' failed: ' + res['stderr'][-400:])
            return res

        def inside(name, cmd, timeout=120, check=True):
            return run(name, 'docker exec ' + CONTAINER + ' sh -c ' + shlex.quote(cmd),
                       timeout=timeout, check=check)

        before = json.loads(inside(
            'metrics_before',
            "curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8020/metrics")["stdout"])
        report['metrics_before'] = before
        if before['active'] or before['queued']:
            raise RuntimeError('Backend busy; refusing to run device fault injection')

        dest = inside('container_dir', 'mktemp -d /tmp/otp-security-fault.XXXXXX')['stdout'].strip()
        stage = run('stage', 'mktemp -d /tmp/otp-security-fault-stage.XXXXXX')['stdout'].strip()

        # engine sources: copy, never build in the live tree
        inside('copy_engine_sources',
               'cp ' + SRC + '/*.h ' + SRC + '/st35.c ' + SRC + '/q8_ops.c '
               + shlex.quote(dest) + '/')
        report['tested_engine_source_sha256'] = inside(
            'engine_source_hash',
            'sha256sum ' + shlex.quote(dest) + '/q8_ops.c')['stdout'].split()[0]

        for path in (probe, shim):
            remote.put('cvm', path, stage + '/' + path.name)
            run('copy_' + path.name,
                'docker cp ' + shlex.quote(stage + '/' + path.name) + ' '
                + shlex.quote(CONTAINER + ':' + dest + '/' + path.name))

        inside('compile_shim',
               'cd ' + shlex.quote(dest) + ' && timeout -k 3 90 gcc -O2 -fPIC -shared '
               'security_fault_getrandom.c -o fake_getrandom.so -ldl', timeout=120)
        inside('compile_probe',
               'cd ' + shlex.quote(dest) + ' && timeout -k 3 300 g++ ' + CFLAGS
               + ' -I' + CANN + '/include -x c++ security_fault_injection.c st35.c q8_ops.c '
               '-o faultinj -L' + CANN + '/lib64 ' + LIBS, timeout=360)

        res = inside('run_cases',
                     'cd ' + shlex.quote(dest) + ' && rm -f /tmp/otp_fault_arm && '
                     'LD_PRELOAD=' + dest + '/fake_getrandom.so '
                     'LD_LIBRARY_PATH=' + CANN + '/lib64:$LD_LIBRARY_PATH '
                     './faultinj ' + MODEL + ' 2>faultinj.err; echo "EXIT=$?"; '
                     'echo "----STDERR----"; tail -40 faultinj.err',
                     timeout=600, check=False)
        raw = res['stdout']
        report['raw_tail'] = raw[-4000:]

        doc = None
        blob = raw.split('EXIT=')[0].strip()
        if blob:
            try:
                doc = json.loads(blob)
            except json.JSONDecodeError:
                start = blob.find('{')
                if start >= 0:
                    doc = json.loads(blob[start:])
        if doc is None:
            raise RuntimeError('probe produced no JSON; see raw_tail')
        report['cases'] = doc['cases']
        report['pass_count'] = doc['pass']
        report['fail_count'] = doc['fail']

        inside('disarm', 'rm -f /tmp/otp_fault_arm', check=False)

        after = json.loads(inside(
            'metrics_after',
            "curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8020/metrics")["stdout"])
        report['metrics_after'] = after
        report['backend_requests_unchanged'] = before['requests'] == after['requests']
        report['backend_idle_after'] = after['active'] == 0 and after['queued'] == 0

        health = inside('engine_health',
                        "curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8020/healthz",
                        check=False)['stdout'].strip()
        report['engine_healthz_after'] = health[:400]

        inside('cleanup', 'rm -rf ' + shlex.quote(dest), check=False)
        run('cleanup_stage', 'rm -rf ' + shlex.quote(stage), check=False)

        by_name = {c['case']: c for c in doc['cases']}
        report['findings'] = {
            'malformed_request_aborts': all(
                by_name.get(n, {}).get('passed') for n in
                ('shape_K_not_mult32', 'shape_N_not_mult16', 'unsupported_split')),
            'csprng_failure_aborts': by_name.get('csprng_failure', {}).get('passed', False),
            'single_row_detects_device_fault':
                by_name.get('device_corrupt_M1', {}).get('passed', False),
            'batch_path_silent_on_device_fault':
                by_name.get('device_corrupt_M4_silent', {}).get('passed', False),
            'device_weight_restored':
                by_name.get('restore_check_M4', {}).get('passed', False),
        }
        report['passed'] = bool(
            doc['fail'] == 0
            and report['backend_requests_unchanged']
            and report['backend_idle_after']
            and report['findings']['device_weight_restored'])
    except Exception as exc:
        report['error_type'] = type(exc).__name__
        report['error'] = str(exc)
    finally:
        if remote:
            try:
                remote.run('cvm', 'docker exec ' + CONTAINER
                           + ' sh -c "rm -f /tmp/otp_fault_arm"', timeout=30)
            except Exception:
                pass
            remote.close()
        report['finished_ns'] = time.time_ns()
        with (args.output_dir / 'result.json').open('x', encoding='utf-8') as out:
            json.dump(report, out, ensure_ascii=False, indent=2)
    print(json.dumps({k: report.get(k) for k in
                      ('passed', 'error', 'pass_count', 'fail_count', 'findings',
                       'backend_requests_unchanged')}, ensure_ascii=False, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
