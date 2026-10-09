"""FEC-07 / FEC-08: can the密态 path be downgraded to plaintext at run time?

Sends the same prompt to the engine with a series of request fields that would, if honoured,
disable blinding (blind=0, plain=true, mode=plain, otp=false, r_scale=0 ...). If the engine
ignores them, every response must be byte-identical to the baseline and the reported mode must
stay shannon_rns_otp. Also checks statically where the blinding mode can be set at all.
Read-only: ordinary inference requests, no configuration or service changes.
"""
import argparse
import json
from pathlib import Path
import shlex
import time

from security_remote import Remote

ENGINE = 'http://127.0.0.1:8020'
# Fields that a careless implementation might honour as a "give me plaintext" switch.
DOWNGRADE_FIELDS = [
    {'blind': 0},
    {'plain': True},
    {'mode': 'plain'},
    {'otp': False},
    {'disable_otp': True},
    {'r_scale': 0},
    {'blind_mode': 'plain'},
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--output-dir', type=Path, required=True)
    ap.add_argument('--max-tokens', type=int, default=8)
    args = ap.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)

    prompt_ids = [101, 202, 303, 404, 505, 606]
    report = {'started_ns': time.time_ns(), 'passed': False,
              'scope': 'run-time downgrade attempts against the OTP engine; ordinary requests only',
              'prompt_token_ids': prompt_ids, 'attempts': []}
    remote = None
    try:
        remote = Remote()

        def run(name, cmd, timeout=180, check=True):
            res = remote.run('cvm', cmd, timeout=timeout)
            report.setdefault('steps', []).append(
                {'name': name, 'exit_code': res['exit_code'], 'stdout': res['stdout'][-1200:]})
            if check and res['exit_code']:
                raise RuntimeError(name + ' failed')
            return res['stdout'].strip()

        def health():
            return json.loads(run('health', "curl --noproxy '*' -fsS --max-time 8 " + ENGINE + "/healthz"))

        def infer(name, extra):
            body = {'prompt_token_ids': prompt_ids, 'max_tokens': args.max_tokens,
                    'temperature': 0, 'ignore_eos': True, 'stream': False}
            body.update(extra)
            payload = json.dumps(body)
            out = run(name, "curl --noproxy '*' -fsS --max-time 300 -X POST "
                            "-H 'Content-Type: application/json' -d " + shlex.quote(payload)
                            + ' ' + ENGINE + '/v1/chat/completions', timeout=360)
            return json.loads(out)

        before = health()
        report['health_before'] = before
        if before.get('active') or before.get('queued'):
            raise RuntimeError('Backend busy')

        baseline = infer('baseline', {})
        base_tokens = baseline.get('completion_token_ids')
        base_mode = (baseline.get('otp') or {}).get('mode')
        report['baseline'] = {'tokens': base_tokens, 'mode': base_mode}
        if not base_tokens:
            raise RuntimeError('No baseline tokens')

        for i, extra in enumerate(DOWNGRADE_FIELDS):
            doc = infer('attempt_%d' % i, extra)
            tokens = doc.get('completion_token_ids')
            mode = (doc.get('otp') or {}).get('mode')
            report['attempts'].append({
                'field': extra,
                'tokens_identical': tokens == base_tokens,
                'mode': mode,
                'mode_unchanged': mode == base_mode,
                'error': doc.get('error'),
            })

        after = health()
        report['health_after'] = after
        report['mode_stable'] = before.get('mode') == after.get('mode') == 'shannon_rns_otp'

        # Where can the blinding mode be set at all?
        src = run('static_blind_sites',
                  "grep -n 'g_blind' /data/otp_c35/serve35_cb.c | head -20", check=False)
        report['static_g_blind_sites'] = src.splitlines()

        all_identical = all(a['tokens_identical'] for a in report['attempts'])
        all_mode_ok = all(a['mode_unchanged'] for a in report['attempts'])
        report['no_downgrade_accepted'] = all_identical and all_mode_ok
        report['passed'] = bool(all_identical and all_mode_ok and report['mode_stable'])
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
                      ('passed', 'error', 'no_downgrade_accepted', 'mode_stable')}, ensure_ascii=False))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
