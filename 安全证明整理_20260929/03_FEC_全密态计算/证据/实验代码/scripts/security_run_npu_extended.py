"""Opt-in independent synthetic NPU samples; no deployment or production payloads."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import time
from security_remote import Remote, PROJECT

RNG_SHA256 = '618b8e5543ae4742d3a1e5ce9a39ae199885ada5f0e366970c8eca8dcbc39555'
SHAPES = ((1, 32, 16), (2, 128, 32), (4, 256, 64), (4, 32, 64), (1, 256, 32), (2, 128, 16))


def semantic_pass(execution):
    events = [json.loads(line) for line in execution['stdout'].splitlines() if line.startswith('{')]
    cases = [e for e in events if e.get('event') == 'case']
    summary = [e for e in events if e.get('event') == 'summary']
    scope = [e for e in events if e.get('event') == 'scope']
    expected = {(m, k, n, pattern, path, repeat) for m, k, n in SHAPES
                for pattern in ('zero', 'positive_extreme', 'negative_extreme', 'sparse')
                for path in ('raw', 'raw_split') for repeat in (0, 1)}
    actual = {(e['M'], e['K'], e['N'], e['pattern'], e['path'], e['repeat']) for e in cases}
    if execution['exit_code'] != 0 or len(cases) != 96 or actual != expected:
        return False
    if len(scope) != 1 or scope[0].get('cpu_auto_correction') is not False:
        return False
    if len(summary) != 1 or summary[0].get('cases') != 96 or summary[0].get('failed_cases_or_cleanup') != 0 or summary[0].get('pass') is not True:
        return False
    by_key = {(e['M'], e['K'], e['N'], e['pattern'], e['path'], e['repeat']): e for e in cases}
    for key, e in by_key.items():
        if not (e.get('pass') is True and e.get('rc') == 0 and e.get('output_mismatches') == 0
                and e.get('raw_integer_limb_mismatches') == 0 and e.get('H2D') == 1 and e.get('D2H') == 1):
            return False
        if key[-1] == 1 and (e.get('repeat_fingerprint_differs') is not True or
                             e.get('h2d_fnv1a64') == by_key[key[:-1] + (0,)].get('h2d_fnv1a64')):
            return False
    return True


def metrics(remote):
    result = remote.run('cvm', "curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8020/metrics")
    if result['exit_code']:
        raise RuntimeError('Metrics unavailable')
    parsed = json.loads(result['stdout'])
    if not all(key in parsed for key in ('active', 'queued', 'requests')):
        raise RuntimeError('Incomplete metrics')
    return parsed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--run-synthetic', action='store_true', required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    report = {'started_ns': time.time_ns(), 'pass': False,
              'scope': '96 independent synthetic samples, direct linked memcpy only; no physical PCIe capture or production trace',
              'fingerprint_claim': 'sample non-repetition only, FNV-1a64 not cryptographic proof'}
    remote = None
    try:
        frozen = PROJECT / 'delivery/OTP35B_CB_V11_20260903'
        files = [frozen / n for n in ('q8_ops.c', 'q8_ops.h', 'st35.c', 'st35.h')]
        files += [PROJECT / 'otp_rng.h', PROJECT / 'scripts/security_npu_extended_probe.cpp']
        identities = files + [Path(__file__).resolve(), PROJECT / 'scripts/security_remote.py',
                              PROJECT / 'benchmark/three_way_controlled_rerun/run_controlled_three_way_remote.py']
        report['source_sha256'] = {str(f.relative_to(PROJECT)): hashlib.sha256(f.read_bytes()).hexdigest() for f in identities}
        if report['source_sha256']['otp_rng.h'] != RNG_SHA256:
            raise RuntimeError('Current RNG identity changed; review required')
        remote = Remote()
        report['before'] = metrics(remote)
        if report['before']['active'] != 0 or report['before']['queued'] != 0:
            raise RuntimeError('Backend busy; no experiment started')
        paths = []
        for prefix, command in (('/tmp/otp-security-npu-ext-stage-', 'mktemp -d '),
                                ('/tmp/otp-security-npu-ext-', 'docker exec otp-c35-cb mktemp -d ')):
            result = remote.run('cvm', command + prefix + 'XXXXXX')
            path = result['stdout'].strip()
            if result['exit_code'] or not path.startswith(prefix) or any(c.isspace() for c in path):
                raise RuntimeError('Unexpected temporary path')
            paths.append(path)
        stage, directory = paths
        report.update(staging=stage, container_directory=directory)
        for file in files:
            remote.put('cvm', file, stage + '/' + file.name)
        report['copy'] = remote.run('cvm', 'docker cp ' + shlex.quote(stage + '/.') + ' ' + shlex.quote('otp-c35-cb:' + directory + '/'))
        if report['copy']['exit_code']:
            raise RuntimeError('Copy failed')
        prefix = 'docker exec otp-c35-cb sh -c '
        cann = '/usr/local/Ascend/cann-9.1.0/aarch64-linux'
        build = ('cd ' + shlex.quote(directory) + ' && timeout 55 g++ -O2 -march=armv8.6-a+sve+i8mm+bf16 -std=c++17 -Wall -Wno-unused-function -Wno-deprecated-declarations -pthread -fopenmp -I' + cann + '/include -x c++ security_npu_extended_probe.cpp q8_ops.c st35.c -o probe -L' + cann + '/lib64 -lascendcl -lnnopbase -lopapi -L/data/ascendc/build -lbdszblind -Wl,-rpath,/data/ascendc/build -Wl,--wrap=aclrtMemcpy -lm')
        report['build_command'] = build
        report['compile'] = remote.run('cvm', prefix + shlex.quote(build), timeout=60)
        report['library_identity'] = remote.run('cvm', prefix + shlex.quote('sha256sum /data/ascendc/build/libbdszblind.so'))
        report['remote_source_identity'] = remote.run('cvm', prefix + shlex.quote('cd ' + shlex.quote(directory) + ' && sha256sum ' + ' '.join(shlex.quote(f.name) for f in files)))
        remote_hashes = {line.split()[1]: line.split()[0] for line in report['remote_source_identity']['stdout'].splitlines()}
        if report['remote_source_identity']['exit_code'] or any(remote_hashes.get(f.name) != hashlib.sha256(f.read_bytes()).hexdigest() for f in files):
            raise RuntimeError('Remote source identity mismatch')
        if report['compile']['exit_code'] or report['library_identity']['exit_code']:
            raise RuntimeError('Compile or library identity failed')
        report['pre_execution'] = metrics(remote)
        if report['pre_execution']['active'] != 0 or report['pre_execution']['queued'] != 0:
            raise RuntimeError('Backend became busy; execution skipped')
        command = ('cd ' + shlex.quote(directory) + ' && LD_LIBRARY_PATH=' + cann + '/lib64:/data/ascendc/build:/usr/local/Ascend/driver/lib64/driver:/usr/local/Ascend/driver/lib64/common OMP_NUM_THREADS=1 timeout -k 3 50 ./probe --run-synthetic')
        report['execution_command'] = command
        report['execution'] = remote.run('cvm', prefix + shlex.quote(command), timeout=60)
        report['semantic_pass'] = semantic_pass(report['execution'])
    except Exception as exc:
        report['error_type'] = type(exc).__name__
    finally:
        if remote:
            try:
                report['after'] = metrics(remote)
                report['backend_idle_after'] = report['after']['active'] == 0 and report['after']['queued'] == 0
                report['backend_request_count_unchanged'] = report['after']['requests'] == report.get('before', {}).get('requests')
            except Exception as exc:
                report['after_error_type'] = type(exc).__name__
            try:
                remote.close()
            except Exception as exc:
                report['close_error_type'] = type(exc).__name__
        report['pass'] = (report.get('semantic_pass') is True and report.get('backend_idle_after') is True
                          and report.get('backend_request_count_unchanged') is True and 'error_type' not in report)
        report['finished_ns'] = time.time_ns()
        with (args.output_dir / 'result.json').open('x', encoding='utf-8') as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
        print(json.dumps({'directory': str(args.output_dir), 'pass': report['pass'], 'error_type': report.get('error_type')}))
    return 0 if report['pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
