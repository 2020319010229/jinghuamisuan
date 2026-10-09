"""Compile real candidate HTTP/scheduler with a model mock in isolated CVM /tmp.

No model files, NPU calls, production files, listeners, or service changes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import tarfile
import tempfile
from security_remote import Remote


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).resolve().parents[1] / 'security_fixes/20260917_cancel/engine'
    files = ['serve35_cb.c', 'otp_cancel.h', 'tests/model35.h', 'tests/test_cancel.c']
    report = {'scope': 'isolated model-mock only; no deployment or NPU',
              'sha256': {f: hashlib.sha256((source / f).read_bytes()).hexdigest() for f in files}}
    remote = None
    try:
        remote = Remote()
        def run(key, command, timeout=60):
            result = remote.run('cvm', command, timeout=timeout)
            report[key] = result
            return result
        stage = run('create_stage', 'mktemp -d /tmp/otp-security-cancel-engine-stage.XXXXXX')['stdout'].strip()
        dest = run('create_container_dir', 'docker exec otp-c35-cb mktemp -d /tmp/otp-security-cancel-engine-test.XXXXXX')['stdout'].strip()
        if not stage.startswith('/tmp/otp-security-cancel-engine-stage.') or not dest.startswith('/tmp/otp-security-cancel-engine-test.'):
            raise RuntimeError('Unexpected temporary path')
        report.update(staging=stage, container_directory=dest)
        with tempfile.TemporaryDirectory(prefix='otp-cancel-upload-') as local:
            bundle = Path(local) / 'candidate.tar'
            with tarfile.open(bundle, 'w') as tar:
                for name in files:
                    tar.add(source / name, arcname=name, recursive=False)
            remote.put('cvm', bundle, stage + '/candidate.tar')
        copied = run('copy', 'docker cp ' + shlex.quote(stage+'/candidate.tar') + ' ' + shlex.quote('otp-c35-cb:'+dest+'/candidate.tar'))
        if copied['exit_code']:
            raise RuntimeError('Copy failed')
        def inside(key, command, timeout=60):
            return run(key, 'docker exec otp-c35-cb sh -c '+shlex.quote('cd '+shlex.quote(dest)+' && '+command), timeout)
        if inside('extract', 'tar -xf candidate.tar')['exit_code']:
            raise RuntimeError('Extract failed')
        compile_cmd = 'g++ -x c++ -std=c++17 -O1 -g -Wall -Wextra -pthread -Itests tests/test_cancel.c'
        if not inside('compile', 'timeout 45 '+compile_cmd+' -o cancel-test')['exit_code']:
            inside('test', 'timeout 45 ./cancel-test')
        if not inside('compile_sanitized', 'timeout 45 '+compile_cmd+' -fsanitize=address,undefined -fno-omit-frame-pointer -o cancel-test-sanitized')['exit_code']:
            inside('test_sanitized', 'ASAN_OPTIONS=detect_leaks=0 timeout 45 ./cancel-test-sanitized')
        if not inside('compile_ubsan', 'timeout 45 '+compile_cmd+' -fsanitize=undefined -fno-sanitize-recover=all -o cancel-test-ubsan')['exit_code']:
            inside('test_ubsan', 'timeout 45 ./cancel-test-ubsan')
    except Exception as exc:
        report['error_type'] = type(exc).__name__
    finally:
        if remote:
            remote.close()
        with (args.output_dir/'result.json').open('x', encoding='utf-8') as out:
            json.dump(report, out, ensure_ascii=False, indent=2)
        print(json.dumps({k:v.get('exit_code') for k,v in report.items() if isinstance(v,dict) and 'exit_code' in v}))
    required_pass = report.get('test', {}).get('exit_code') == 0
    optional_failed = any(report[k]['exit_code'] for k in ('test_sanitized', 'test_ubsan') if k in report)
    return 0 if required_pass and not optional_failed else 1


if __name__ == '__main__':
    raise SystemExit(main())
