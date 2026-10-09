"""TDC-05 / FEC cleanup: can a later task read a previous task's device memory?

Runs writer and reader as separate processes inside the engine container, covering both an
orderly free and a process exit that leaves reclamation to the driver. The reader's
self-check proves the read path works, so a zero result is meaningful. Synthetic markers
only; the production engine is not touched and the probe runs while the backend is idle.
"""
import argparse
import json
from pathlib import Path
import secrets
import shlex
import time

from security_remote import Remote

CANN = '/usr/local/Ascend/cann-9.1.0/aarch64-linux'
CONTAINER = 'otp-c35-cb'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--output-dir', type=Path, required=True)
    ap.add_argument('--megabytes', type=int, default=256)
    ap.add_argument('--rounds', type=int, default=2)
    args = ap.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)

    source = Path(__file__).with_name('security_device_memory_residue.cpp')
    report = {'started_ns': time.time_ns(), 'passed': False,
              'scope': 'cross-process device memory reuse inside the engine container; '
                       'synthetic markers; production engine untouched',
              'megabytes': args.megabytes, 'rounds': []}
    remote = None
    try:
        remote = Remote()

        def run(name, cmd, timeout=120, check=True):
            res = remote.run('cvm', cmd, timeout=timeout)
            report.setdefault('steps', []).append(
                {'name': name, 'exit_code': res['exit_code'],
                 'stdout': res['stdout'][-1500:], 'stderr': res['stderr'][-800:]})
            if check and res['exit_code']:
                raise RuntimeError(name + ' failed: ' + res['stderr'][-300:])
            return res['stdout'].strip()

        def inside(name, cmd, timeout=120, check=True):
            return run(name, 'docker exec ' + CONTAINER + ' sh -c ' + shlex.quote(cmd),
                       timeout=timeout, check=check)

        before = json.loads(run('metrics_before',
                                "curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8020/metrics"))
        report['metrics_before'] = before
        if before['active'] or before['queued']:
            raise RuntimeError('Backend busy; refusing to allocate device memory')

        stage = run('stage', 'mktemp -d /tmp/otp-security-devres-stage.XXXXXX')
        dest = inside('container_dir', 'mktemp -d /tmp/otp-security-devres.XXXXXX')
        remote.put('cvm', source, stage + '/probe.cpp')
        run('copy', 'docker cp ' + shlex.quote(stage + '/probe.cpp') + ' '
            + shlex.quote(CONTAINER + ':' + dest + '/probe.cpp'))
        inside('compile',
               'cd ' + shlex.quote(dest) + ' && timeout -k 3 90 g++ -O2 -std=c++17 -D_GNU_SOURCE '
               '-I' + CANN + '/include probe.cpp -o devres -L' + CANN + '/lib64 -lascendcl',
               timeout=120)

        for index in range(args.rounds):
            marker = 'DEVRESIDUE' + secrets.token_hex(11)
            mode = 'write' if index % 2 == 0 else 'write-nofree'
            w = inside('write_%d' % index,
                       'cd ' + shlex.quote(dest) + ' && ./devres ' + mode + ' '
                       + shlex.quote(marker) + ' ' + str(args.megabytes), timeout=180)
            r = inside('read_%d' % index,
                       'cd ' + shlex.quote(dest) + ' && ./devres read '
                       + shlex.quote(marker) + ' ' + str(args.megabytes), timeout=180)
            wdoc = json.loads(w.splitlines()[-1]) if w else {}
            rdoc = json.loads(r.splitlines()[-1]) if r else {}
            report['rounds'].append({
                'round': index + 1, 'writer_mode': mode,
                'writer': wdoc, 'reader': rdoc,
                'marker_prefix': marker[:14] + '…',
                'residue_found': rdoc.get('marker_hits', -1) > 0,
                'read_path_valid': rdoc.get('self_check_hits', 0) > 0,
            })

        after = json.loads(run('metrics_after',
                               "curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8020/metrics"))
        report['metrics_after'] = after
        report['backend_requests_unchanged'] = before['requests'] == after['requests']
        report['backend_idle_after'] = after['active'] == 0 and after['queued'] == 0

        inside('cleanup', 'rm -rf ' + shlex.quote(dest), check=False)
        run('cleanup_stage', 'rm -rf ' + shlex.quote(stage), check=False)

        all_clean = all(not r['residue_found'] for r in report['rounds'])
        all_valid = all(r['read_path_valid'] for r in report['rounds'])
        report['no_cross_process_residue'] = all_clean
        report['read_path_validated'] = all_valid
        report['passed'] = bool(all_clean and all_valid and report['rounds']
                                and report['backend_requests_unchanged'])
    except Exception as exc:
        report['error_type'] = type(exc).__name__
        report['error'] = str(exc)
    finally:
        if remote:
            remote.close()
        report['finished_ns'] = time.time_ns()
        with (args.output_dir / 'result.json').open('x', encoding='utf-8') as out:
            json.dump(report, out, ensure_ascii=False, indent=2)
    print(json.dumps({k: report.get(k) for k in
                      ('passed', 'error', 'no_cross_process_residue', 'read_path_validated',
                       'backend_requests_unchanged')}, ensure_ascii=False))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
