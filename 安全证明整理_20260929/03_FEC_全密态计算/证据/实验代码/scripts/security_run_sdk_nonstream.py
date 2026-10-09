"""Upload/run the bounded nonstream probe; require explicit JSON success."""
import argparse
import json
from pathlib import Path
import shlex
import time
from security_remote import Remote, credentials


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--output-dir', required=True, type=Path)
    p.add_argument('--base-url')
    p.add_argument('--gateway-url')
    p.add_argument('--client-dir', default='/root/client')
    args = p.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    remote = None
    report = {'started_ns': time.time_ns(), 'passed': False}
    try:
        remote = Remote()
        created = remote.run('host', 'mktemp -d /tmp/otp-security-nonstream-20260917.XXXXXX')
        directory = created['stdout'].strip()
        if created['exit_code'] or not directory.startswith('/tmp/otp-security-nonstream-20260917.') or '/' in directory[len('/tmp/'):]:
            raise RuntimeError('Invalid temporary directory')
        report['directory'] = directory
        script = 'security_sdk_nonstream_probe.py'
        remote.put('host', Path(__file__).with_name(script), directory + '/' + script)
        command = ['timeout', '240', 'python3', directory + '/' + script, '--directory', directory,
                   '--client-dir', args.client_dir, '--base-url', args.base_url or 'http://' + credentials.CVM + ':8101',
                   '--gateway-url', args.gateway_url or 'http://' + credentials.CVM + ':8000']
        result = remote.run('host', shlex.join(command), timeout=250)
        # Never persist arbitrary process output: the structured probe is allowlisted.
        report['execution_exit_code'] = result['exit_code']
        dest = args.output_dir / 'nonstream_result.json'
        remote.get('host', directory + '/nonstream_result.json', dest)
        probe = json.loads(dest.read_text(encoding='utf-8'))
        report['passed'] = result['exit_code'] == 0 and probe.get('passed') is True and bool(probe.get('tests')) and all(x.get('passed') is True for x in probe['tests'])
    except Exception as exc:
        report['error_type'] = type(exc).__name__
    finally:
        if remote:
            remote.close()
        report['finished_ns'] = time.time_ns()
        with (args.output_dir / 'orchestration.json').open('x', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
    print(json.dumps(report))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
