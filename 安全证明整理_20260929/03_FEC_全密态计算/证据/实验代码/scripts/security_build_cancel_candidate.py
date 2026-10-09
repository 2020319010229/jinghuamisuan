"""Compile a cancellation candidate beside a byte-reproduced live baseline. No deploy."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import tarfile
import time
from security_remote import Remote, PROJECT

EXPECTED = '3cdae626266c4955003eb3f33f2ce4a466c819604472b5e56c4a0806bdd40e98'


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--output-dir', type=Path, required=True)
    args = p.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    report = {'started_ns': time.time_ns(), 'passed': False,
              'scope': 'isolated full engine build; no model loading, service changes, or deployment'}
    r = None
    try:
        frozen = PROJECT / 'delivery/OTP35B_CB_V11_20260903'
        candidate = PROJECT / 'security_fixes/20260917_cancel/engine'
        files = sorted(list(frozen.glob('*.c')) + list(frozen.glob('*.h')) + [frozen / 'Makefile'])
        hashes = {}
        archive = args.output_dir / 'build_inputs.tar'
        with tarfile.open(archive, 'w') as t:
            for phase in ('baseline', 'candidate'):
                for file in files:
                    source = PROJECT / 'otp_rng.h' if file.name == 'otp_rng.h' else file
                    if phase == 'candidate' and file.name == 'serve35_cb.c':
                        source = candidate / file.name
                    name = phase + '/' + file.name
                    hashes[name] = hashlib.sha256(source.read_bytes()).hexdigest()
                    t.add(source, arcname=name)
                if phase == 'candidate':
                    source = candidate / 'otp_cancel.h'
                    hashes['candidate/otp_cancel.h'] = hashlib.sha256(source.read_bytes()).hexdigest()
                    t.add(source, arcname='candidate/otp_cancel.h')
        report['source_sha256'] = hashes
        r = Remote()

        def run(name, command, timeout=40):
            result = r.run('cvm', command, timeout=timeout)
            report[name] = result
            if result['exit_code']:
                raise RuntimeError(name + ' failed')
            return result['stdout'].strip()

        def inside(name, command, timeout=40):
            return run(name, 'docker exec otp-c35-cb sh -c ' + shlex.quote(command), timeout)

        report['before'] = json.loads(run('metrics_before', "curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8020/metrics"))
        if inside('online_before', 'sha256sum /opt/otp35/bin/serve35_cb').split()[0] != EXPECTED:
            raise RuntimeError('Live baseline drift')
        stage = run('new_stage', 'mktemp -d /tmp/otp-security-cancel-build-stage.XXXXXX')
        directory = run('new_build', 'docker exec otp-c35-cb mktemp -d /tmp/otp-security-cancel-build.XXXXXX')
        if not stage.startswith('/tmp/otp-security-cancel-build-stage.') or not directory.startswith('/tmp/otp-security-cancel-build.'):
            raise RuntimeError('Invalid temporary path')
        report['stage'] = stage
        report['container_directory'] = directory
        r.put('cvm', archive, stage + '/inputs.tar')
        run('copy', 'docker cp ' + shlex.quote(stage + '/inputs.tar') + ' ' + shlex.quote('otp-c35-cb:' + directory + '/inputs.tar'))
        inside('extract', 'tar -xf ' + shlex.quote(directory + '/inputs.tar') + ' -C ' + shlex.quote(directory))
        for phase in ('baseline', 'candidate'):
            inside(phase + '_build', 'cd ' + shlex.quote(directory + '/' + phase) + ' && timeout -k 3 150 make serve35_cb', 165)
            value = inside(phase + '_identity', 'sha256sum ' + shlex.quote(directory + '/' + phase + '/serve35_cb')).split()[0]
            report[phase + '_sha256'] = value
            if phase == 'baseline' and value != EXPECTED:
                raise RuntimeError('Full baseline build did not reproduce live binary')
        report['after'] = json.loads(run('metrics_after', "curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8020/metrics"))
        report['online_unchanged'] = inside('online_after', 'sha256sum /opt/otp35/bin/serve35_cb').split()[0] == EXPECTED
        report['candidate_path'] = directory + '/candidate/serve35_cb'
        report['passed'] = report['online_unchanged']
    except Exception as exc:
        report['error_type'] = type(exc).__name__
        report['error'] = str(exc)
    finally:
        if r:
            r.close()
        report['finished_ns'] = time.time_ns()
        with (args.output_dir / 'result.json').open('x', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
    print(json.dumps({k: report.get(k) for k in ('passed', 'error', 'baseline_sha256', 'candidate_sha256', 'candidate_path', 'online_unchanged')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
