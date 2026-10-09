"""FEC end-to-end correctness: the same OTP engine reached through the plaintext entry and
through the encrypted entry must return identical output.

Every round uses a fresh unique prompt so a cache hit cannot manufacture agreement, and the
entry order alternates so a warm-up effect cannot favour one path. Read-only with respect to
deployment: it only sends normal inference requests.
"""
import argparse
import hashlib
import json
from pathlib import Path
import secrets
import shlex
import time

from security_remote import Remote


def content_of(doc):
    try:
        return doc['choices'][0]['message']['content']
    except Exception:
        try:
            return doc['choices'][0]['text']
        except Exception:
            return None


def usage_of(doc):
    u = doc.get('usage') or {}
    return {'prompt_tokens': u.get('prompt_tokens'), 'completion_tokens': u.get('completion_tokens')}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--output-dir', type=Path, required=True)
    ap.add_argument('--rounds', type=int, default=3)
    ap.add_argument('--max-tokens', type=int, default=24)
    args = ap.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)

    report = {'started_ns': time.time_ns(), 'passed': False,
              'scope': 'same OTP engine via plaintext and encrypted entry on :8000; '
                       'unique prompt per round; alternating order',
              'max_tokens': args.max_tokens, 'rounds': []}
    remote = None
    try:
        remote = Remote()

        def call(prompt, encrypted):
            cmd = ('cd /data/otp_c35 && python3 tee_client.py --url http://127.0.0.1:8000 '
                   '--prompt ' + shlex.quote(prompt) + ' --max-tokens ' + str(args.max_tokens)
                   + ('' if encrypted else ' --plaintext'))
            started = time.monotonic()
            res = remote.run('cvm', cmd, timeout=1200)
            if res['exit_code']:
                raise RuntimeError(('encrypted' if encrypted else 'plaintext')
                                   + ' entry failed: ' + res['stderr'][-300:])
            body = res['stdout'].strip()
            start = body.find('{')
            doc = json.loads(body[start:] if start >= 0 else body)
            return doc, (time.monotonic() - started) * 1000

        all_match = True
        for index in range(args.rounds):
            tag = secrets.token_hex(8)
            prompt = 'sample-%s: explain confidential computing in one sentence.' % tag
            encrypted_first = index % 2 == 0
            order = ['encrypted', 'plaintext'] if encrypted_first else ['plaintext', 'encrypted']
            docs = {}
            timings = {}
            for entry in order:
                docs[entry], timings[entry] = call(prompt, entry == 'encrypted')
            enc_text, pln_text = content_of(docs['encrypted']), content_of(docs['plaintext'])
            match = enc_text is not None and enc_text == pln_text
            all_match = all_match and match
            report['rounds'].append({
                'round': index + 1,
                'prompt_sha256': hashlib.sha256(prompt.encode()).hexdigest(),
                'order': order,
                'match': match,
                'encrypted': {'usage': usage_of(docs['encrypted']),
                              'sha256': hashlib.sha256((enc_text or '').encode()).hexdigest(),
                              'chars': len(enc_text or ''), 'elapsed_ms': round(timings['encrypted'], 1)},
                'plaintext': {'usage': usage_of(docs['plaintext']),
                              'sha256': hashlib.sha256((pln_text or '').encode()).hexdigest(),
                              'chars': len(pln_text or ''), 'elapsed_ms': round(timings['plaintext'], 1)},
                'sample': (enc_text or '')[:80],
            })

        prompts = {r['prompt_sha256'] for r in report['rounds']}
        report['unique_prompts'] = len(prompts) == len(report['rounds'])
        report['all_entries_match'] = all_match
        report['passed'] = bool(all_match and report['unique_prompts'] and report['rounds'])
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
                      ('passed', 'error', 'all_entries_match', 'unique_prompts')}, ensure_ascii=False))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
