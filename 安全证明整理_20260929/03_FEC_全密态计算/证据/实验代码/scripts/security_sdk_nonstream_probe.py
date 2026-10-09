"""Three short live regressions. No policy edits or secret-bearing output."""
import argparse
import asyncio
import contextlib
import hashlib
import json
import logging
import os
from pathlib import Path
import secrets
import sys
import time
import urllib.request


async def run(args, report):
    sys.path.insert(0, args.client_dir)
    import client as sdk
    from utils.kunpeng_attestation import is_remote_attestation_enabled
    report['remote_attestation_enabled'] = bool(is_remote_attestation_enabled())
    if not report['remote_attestation_enabled']:
        raise RuntimeError('Attestation disabled')
    clients = []
    owned = []
    def check(name, passed):
        report['tests'].append({'name': name, 'passed': bool(passed)})
        if not passed:
            raise RuntimeError('Regression failed')
    settings = dict(model='qwen3.5-35b', max_new_tokens=4, temperature=0.0, top_p=1.0)
    try:
        c = sdk.Client(args.base_url, **settings)
        clients.append(c)
        status, primary = await c.env_init(str(Path(args.directory) / 'certificate.der'), challenge_hex=secrets.token_hex(32))
        if c.dek_id is not None:
            owned.append((c, c.dek_id))
        check('fresh_challenge_initialization', status == 0 and primary is not None and c.connected)
        encoded = await c.Plain_content2Encrypted_content(
            [{'role': 'user', 'plain_content': 'Reply OK.'}], primary)
        check('default_prompt_encrypted', encoded.get('status') == 'succeeded')
        result = await c.Encryption_Generation(
            session_id=c.new_session(prefix='security-nonstream-' + report['run_id']),
            encryption_data=encoded['data']['encryption_data'], stream=False,
            include_reasoning=False, enable_web_search=False, cache_enable=False, **settings)
        check('default_nonstream_response', isinstance(result, dict) and result.get('status') == 'succeeded')
        plain = await c.Encrypted_generation_res2Plain_generation_res(
            result['data'].get('encryption_generationdata_outputdata', ''), primary)
        check('default_nonstream_authenticated_decryption', plain.get('status') == 'succeeded' and bool(plain.get('data', {}).get('plain_generation_outputdata')))

        # A second SDK instance creates only a local test key. The attested first
        # client's default key stays unchanged; explicit dek_id must be honored.
        other = sdk.Client(args.base_url, **settings)
        clients.append(other)
        status, alternate = other.generate_dek()
        if other.dek_id is not None:
            owned.append((other, other.dek_id))
        check('nondefault_key_created', status == 0 and alternate is not None and alternate != primary and c.dek_id == primary)
        status, messages, _, _ = c.encrypt_messages_with_dek([{'role': 'user', 'content': 'Reply OK.'}], alternate)
        check('nondefault_prompt_encrypted', status == 0)
        status, wrapped, length = c.encrypt_dek_with_tee_pubkey(alternate)
        check('nondefault_key_wrapped', status == 0)
        params = dict(settings, messages=messages, documents=[], alg_id=sdk.Alg_id.ALG_SM4_GCM,
                      encrypted_dek=wrapped, encrypted_dek_len=length,
                      encrypted_timestamp=c._encrypt_timestamp_for_request(alternate), timestamp=time.time(),
                      session_id=c.new_session(prefix='security-explicit-' + report['run_id']),
                      stream=False, include_reasoning=False, cache_enable=False, enable_web_search=False)
        check('nondefault_timestamp_encrypted', bool(params['encrypted_timestamp']))
        response = await c.send_message('Inference', params, dek_id=alternate)
        check('nondefault_nonstream_response', isinstance(response, dict) and response.get('status') == 0)
        wire = response['data'].get('encryption_generationdata_outputdata', '')
        plain = await c.Encrypted_generation_res2Plain_generation_res(wire, alternate)
        check('nondefault_authenticated_decryption', plain.get('status') == 'succeeded' and bool(plain.get('data', {}).get('plain_generation_outputdata')))
        wrong = await c.Encrypted_generation_res2Plain_generation_res(wire, primary)
        check('nondefault_response_rejects_default_key', wrong.get('status') != 'succeeded')
        check('default_key_unchanged', c.dek_id == primary)

        def gateway():
            body = {'model': settings['model'], 'messages': [{'role': 'user', 'content': 'Reply OK.'}],
                    'max_tokens': 4, 'temperature': 0, 'stream': False,
                    'chat_template_kwargs': {'enable_thinking': False}}
            req = urllib.request.Request(args.gateway_url.rstrip('/') + '/v1/chat/completions',
                json.dumps(body).encode(), headers={'Content-Type': 'application/json'}, method='POST')
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.status, json.loads(r.read())
        status, response = await asyncio.to_thread(gateway)
        choices = response.get('choices') or []
        content = (choices[0].get('message') or {}).get('content') if choices else None
        check('gateway_plain_nonstream', status == 200 and isinstance(content, str) and bool(content))
        report['gateway_output_sha256'] = hashlib.sha256(content.encode()).hexdigest()
    finally:
        for owner, key in owned:
            removed = owner.remove_dek(key) == 0
            try:
                sdk.CryptoUtils.get_dek(key)
                absent = False
            except (ValueError, KeyError):
                absent = True
            report['tests'].append({'name': 'own_test_key_cleanup', 'passed': removed and absent})
        for c in clients:
            await c.close_connection()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--directory', required=True)
    p.add_argument('--client-dir', default='/root/client')
    p.add_argument('--base-url', required=True)
    p.add_argument('--gateway-url', required=True)
    args = p.parse_args()
    report = {'run_id': secrets.token_hex(10), 'tests': [], 'passed': False}
    logging.disable(logging.CRITICAL)
    # Guard against third-party print/debug statements leaking key material.
    with open(os.devnull, 'w') as sink, contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
        try:
            asyncio.run(asyncio.wait_for(run(args, report), timeout=220))
        except Exception as exc:
            report['error_type'] = type(exc).__name__
    report['passed'] = bool(report['tests']) and not report.get('error_type') and all(x['passed'] for x in report['tests'])
    with (Path(args.directory) / 'nonstream_result.json').open('x', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    print(json.dumps(report))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
