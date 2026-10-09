"""Explicit standalone NPU lifecycle probe; does not modify deployed sources.

Observations distinguish same-process residue from a demonstrated attacker read.
The error run wraps getrandom only in its own executable, never in a service.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import time
from security_remote import Remote, PROJECT

EXPECTED_RNG_SHA256 = '618b8e5543ae4742d3a1e5ce9a39ae199885ada5f0e366970c8eca8dcbc39555'


def final_checks(report):
    runs = report.get('runs', [])
    snapshots = [report.get('before', {}), report.get('after', {}), report.get('final_idle', {})]
    for run in runs:
        snapshots.extend([run.get('idle_before', {}), run.get('idle_after', {})])
    counts = [s.get('requests') for s in snapshots]
    return {
        'no_error': not any(k.endswith('error_type') for k in report),
        'all_runs_pass': len(runs) == 2 and all(r.get('semantic_validation', {}).get('all_checks_pass') is True for r in runs),
        'all_snapshots_idle': all(s.get('active') == 0 and s.get('queued') == 0 for s in snapshots),
        'request_counts_present_and_unchanged': all(isinstance(c, int) and not isinstance(c, bool) for c in counts) and len(set(counts)) == 1,
        'source_hashes_match': report.get('uploaded_hashes_match') is True,
        'rng_hash_pinned': report.get('source_sha256', {}).get('otp_rng.h') == EXPECTED_RNG_SHA256,
    }


def check_events(execution, error_mode):
    events = []
    for line in execution.get('stdout', '').splitlines():
        if line.startswith('{'):
            events.append(json.loads(line))
    cases = [e for e in events if e.get('event') == 'case']
    frees = [e for e in events if e.get('event') == 'pre_free']
    summaries = [e for e in events if e.get('event') == 'summary']
    work = [e for e in events if e.get('event') == 'workspace']
    fresh = [e for e in events if e.get('event') == 'fresh_masks']
    tails = [e for e in events if e.get('event') == 'unused_tail']
    checks = {
        'exit_zero': execution.get('exit_code') == 0,
        'three_expected_cases': len(cases) == 3 and all(e.get('pass') is True for e in cases),
        'real_npu_outputs_match': len(cases) >= 2 and all(e.get('rc') == 0 and e.get('output_mismatches') == 0 for e in cases[:2]),
        'quantized_input_observed': len(work) == 3 and all(e.get('xq_matches_synthetic') is True for e in work),
        'fresh_masks_observed': len(fresh) == 1 and fresh[0].get('r0_changed') is True and fresh[0].get('r1_changed') is True,
        'tail_observation_complete': len(tails) == 5,
        'pre_free_observation_complete': len(frees) == 10 and len({e['buffer'] for e in frees}) == 10,
        'normal_cleanup_complete': len(summaries) == 1 and summaries[0].get('all_tracked_freed') is True and summaries[0].get('workspace_struct_zero') is True and summaries[0].get('failed_cases_or_cleanup') == 0,
        'rng_injection_scope': len(cases) == 3 and (cases[2].get('rc') != 0 and cases[2].get('injected_getrandom_EIO', 0) > 0 if error_mode else all(e.get('injected_getrandom_EIO') == 0 for e in cases)),
    }
    # Residue and nonzero-at-free are recorded outcomes, not harness failures.
    # Two different fingerprints do not establish universal non-reuse.
    return {'checks': checks, 'all_checks_pass': all(checks.values()), 'events': events}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--output-dir', type=Path, required=True)
    a = p.parse_args()
    a.output_dir.mkdir(parents=True, exist_ok=False)
    r = None
    report = {'started_ns': time.time_ns(), 'scope': 'own synthetic process; same-TU observer; no cross-process exploit claim; getrandom EIO only in error child executable'}
    try:
        if hashlib.sha256((PROJECT / 'otp_rng.h').read_bytes()).hexdigest() != EXPECTED_RNG_SHA256:
            raise RuntimeError('Unexpected RNG source')
        r = Remote()
        def metrics():
            result = r.run('cvm', "curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8020/metrics")
            if result['exit_code']:
                raise RuntimeError('Metrics unavailable')
            obj = json.loads(result['stdout'])
            if obj.get('active') != 0 or obj.get('queued') != 0:
                raise RuntimeError('Backend not demonstrably idle')
            return obj
        report['before'] = metrics()
        stage_result = r.run('cvm', 'mktemp -d /tmp/otp-security-workspace-stage.XXXXXX')
        dest_result = r.run('cvm', 'docker exec otp-c35-cb mktemp -d /tmp/otp-security-workspace-probe.XXXXXX')
        stage, dest = stage_result['stdout'].strip(), dest_result['stdout'].strip()
        if stage_result['exit_code'] or dest_result['exit_code'] or not stage.startswith('/tmp/otp-security-workspace-stage.') or not dest.startswith('/tmp/otp-security-workspace-probe.'):
            raise RuntimeError('Unexpected temporary path')
        report.update(staging=stage, container_directory=dest)
        frozen = PROJECT / 'delivery/OTP35B_CB_V11_20260903'
        files = [frozen / name for name in ('q8_ops.c', 'q8_ops.h', 'st35.c', 'st35.h')]
        files += [PROJECT / 'otp_rng.h', PROJECT / 'scripts/security_workspace_probe.cpp']
        report['source_sha256'] = {f.name: hashlib.sha256(f.read_bytes()).hexdigest() for f in files}
        if report['source_sha256']['otp_rng.h'] != EXPECTED_RNG_SHA256:
            raise RuntimeError('RNG source changed')
        report['source_provenance'] = {f.name: str(f) for f in files}
        for f in files:
            r.put('cvm', f, stage + '/' + f.name)
        report['copy'] = r.run('cvm', 'docker cp ' + shlex.quote(stage + '/.') + ' ' + shlex.quote('otp-c35-cb:' + dest + '/'))
        if report['copy']['exit_code']:
            raise RuntimeError('Copy failed')
        prefix = 'docker exec otp-c35-cb sh -c '
        cann = '/usr/local/Ascend/cann-9.1.0/aarch64-linux'
        command = 'cd ' + shlex.quote(dest) + ' && g++ -O2 -march=armv8.6-a+sve+i8mm+bf16 -std=c++17 -Wall -Wno-unused-function -Wno-deprecated-declarations -pthread -fopenmp -I' + cann + '/include -x c++ security_workspace_probe.cpp st35.c -o probe -L' + cann + '/lib64 -lascendcl -lnnopbase -lopapi -L/data/ascendc/build -lbdszblind -Wl,-rpath,/data/ascendc/build -Wl,--wrap=free -Wl,--wrap=getrandom -lm'
        command = command.replace(' && g++ ', ' && timeout -k 3 55 g++ ', 1)
        report['build_command'] = command
        report['compile'] = r.run('cvm', prefix + shlex.quote(command), timeout=60)
        report['identity'] = r.run('cvm', prefix + shlex.quote('cd ' + shlex.quote(dest) + ' && sha256sum q8_ops.c q8_ops.h st35.c st35.h otp_rng.h security_workspace_probe.cpp probe /data/ascendc/build/libbdszblind.so'))
        if report['compile']['exit_code']:
            raise RuntimeError('Compile failed')
        identity_lines = report['identity']['stdout'].splitlines()
        remote_hashes = {line.split()[1]: line.split()[0] for line in identity_lines if len(line.split()) == 2}
        report['uploaded_hashes_match'] = all(remote_hashes.get(name) == digest for name, digest in report['source_sha256'].items())
        if not report['uploaded_hashes_match']:
            raise RuntimeError('Source hash mismatch')
        report['runs'] = []
        for error_mode in (False, True):
            idle = metrics()
            flag = '--run-synthetic-rng-error' if error_mode else '--run-synthetic'
            command = 'cd ' + shlex.quote(dest) + ' && LD_LIBRARY_PATH=' + cann + '/lib64:/data/ascendc/build:/usr/local/Ascend/driver/lib64/driver:/usr/local/Ascend/driver/lib64/common OMP_NUM_THREADS=1 timeout 30 ./probe ' + flag
            command = command.replace(' timeout 30 ', ' timeout -k 3 30 ', 1)
            execution = r.run('cvm', prefix + shlex.quote(command), timeout=45)
            run = {'error_mode': error_mode, 'idle_before': idle, 'execution': execution}
            report['runs'].append(run)
            run['semantic_validation'] = check_events(execution, error_mode)
            run['idle_after'] = metrics()
            if not run['semantic_validation']['all_checks_pass']:
                raise RuntimeError('Probe semantic check failed')
        report['after'] = metrics()
        report['backend_request_count_unchanged'] = report['before'].get('requests') == report['after'].get('requests')
        report['backend_idle_after'] = True
    except Exception as exc:
        report['error_type'] = type(exc).__name__
    finally:
        if r:
            try:
                report['final_metrics'] = r.run('cvm', "curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8020/metrics")
                if report['final_metrics']['exit_code']:
                    raise RuntimeError('Final metrics unavailable')
                report['final_idle'] = json.loads(report['final_metrics']['stdout'])
            except Exception as exc:
                report['final_metrics_error_type'] = type(exc).__name__
            finally:
                try:
                    r.close()
                except Exception as exc:
                    report['close_error_type'] = type(exc).__name__
        report['finished_ns'] = time.time_ns()
        report['final_checks'] = final_checks(report)
        report['pass'] = all(report['final_checks'].values())
        with (a.output_dir / 'result.json').open('x', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(json.dumps({'directory': str(a.output_dir), 'pass': report['pass'], 'error_type': report.get('error_type'), 'compile_exit': report.get('compile', {}).get('exit_code')}))
    return 0 if report['pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
