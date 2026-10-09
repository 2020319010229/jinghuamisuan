"""Cancel only this probe's stream, observe EOF/idle, then test recovery.

The existing cancel API discards the worker abort result. This test therefore
reports observed cancellation/recovery, NOT confirmed device abort or memory wipe.
"""
import argparse
import asyncio
import contextlib
import json
import logging
import os
from pathlib import Path
import secrets
import sys
import time
import urllib.error
import urllib.request


async def run(args, report):
    sys.path.insert(0, args.client_dir)
    import client as sdk
    from utils.kunpeng_attestation import is_remote_attestation_enabled

    def check(name, passed):
        report['tests'].append({'name': name, 'passed': bool(passed)})

    def metrics():
        with urllib.request.urlopen(args.metrics_url, timeout=3) as response:
            raw = json.loads(response.read())
        return {k: raw.get(k) for k in ('requests', 'active', 'queued', 'batch_calls', 'batch_rows', 'scalar_decode_calls')}

    async def idle(label):
        deadline = time.monotonic() + 12
        while True:
            state = await asyncio.to_thread(metrics)
            report.setdefault('metrics', []).append({'phase': label, 'monotonic': time.monotonic(), **state})
            if state.get('active') == 0 and state.get('queued') == 0:
                return state
            if time.monotonic() >= deadline:
                raise TimeoutError('Backend did not become idle')
            await asyncio.sleep(0.4)

    report['remote_attestation_enabled'] = bool(is_remote_attestation_enabled())
    if not report['remote_attestation_enabled']:
        raise RuntimeError('Attestation disabled')
    before = await asyncio.to_thread(metrics)
    report['metrics_before'] = before
    if before.get('active') != 0 or before.get('queued') != 0:
        report['blocked'] = 'Backend not idle; no generation or cancel sent'
        return
    c = None
    key = None
    sid = None
    own_started = False
    own_terminated = False
    cancel_attempted = False

    async def cancel_own(label):
        nonlocal cancel_attempted
        cancel_attempted = True
        uid, resolved_sid = c._resolve_identity(sid)
        if resolved_sid != sid:
            raise RuntimeError('Unexpected session mapping')
        body = {'request_id': secrets.token_hex(12), 'function': 'cancel',
                'params': {'session_id': sid, 'user_id': uid, 'timestamp': time.time()}}
        def post():
            req = urllib.request.Request(args.base_url.rstrip('/') + '/internal/cancel',
                json.dumps(body).encode(), headers=c._http_headers({'Content-Type': 'application/json'}), method='POST')
            try:
                with urllib.request.urlopen(req, timeout=5) as response:
                    return response.status, json.loads(response.read())
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read())
        started = time.monotonic()
        report['metrics_before_cancel'] = await asyncio.to_thread(metrics)
        status, doc = await asyncio.to_thread(post)
        report['metrics_after_cancel_response'] = await asyncio.to_thread(metrics)
        message = str(doc.get('message', ''))
        category = ('accepted_without_worker_abort_detail' if doc.get('code') == 0 else
                    'no_active_generation' if 'no active generation' in message else
                    'ownership_mismatch' if 'does not match user_id' in message else 'rejected')
        row = {'phase': label, 'http_status': status, 'app_code': doc.get('code'),
               'semantic_category': category, 'elapsed_ms': (time.monotonic() - started) * 1000}
        report.setdefault('cancel_calls', []).append(row)
        return status == 200 and doc.get('code') == 0

    async def prepare(session, prompt, limit):
        encoded = await c.Plain_content2Encrypted_content([{'role': 'user', 'plain_content': prompt}], key)
        if encoded.get('status') != 'succeeded':
            raise RuntimeError('Prompt encryption failed')
        return await c.Encryption_Generation(session_id=session, encryption_data=encoded['data']['encryption_data'],
            model='qwen3.5-35b', max_new_tokens=limit, temperature=0.0, top_p=1.0,
            include_reasoning=False, cache_enable=False, enable_web_search=False, stream=True)

    async def decrypt(item):
        method = (c.Encrypted_reasoning_res2Plain_reasoning_res if item.get('field') == 'reasoning'
                  else c.Encrypted_generation_res2Plain_generation_res)
        result = await method(item['encrypted_delta'], key)
        if result.get('status') != 'succeeded':
            raise RuntimeError('Delta authentication failed')
        field = 'plain_reasoning_outputdata' if item.get('field') == 'reasoning' else 'plain_generation_outputdata'
        return len(result.get('data', {}).get(field, ''))

    try:
        c = sdk.Client(args.base_url, model='qwen3.5-35b', max_new_tokens=64, temperature=0.0)
        status, key = await c.env_init(str(Path(args.directory) / 'certificate.der'), challenge_hex=secrets.token_hex(32))
        if status != 0 or key is None or not c.connected:
            raise RuntimeError('Fresh attestation initialization failed')
        check('fresh_attestation_initialization', True)
        prompt = 'Count from 1 to 100, writing every integer in order. Do not stop early.'
        reference = {'delta_events': 0, 'done': False, 'reported_output_tokens': None, 'max_new_tokens': 32}
        report['reference'] = reference
        reference_started = time.monotonic()
        stream = await prepare(c.new_session(prefix='security-cancel-reference-' + report['run_id']), prompt, 32)
        async for item in stream:
            if item.get('event') == 'delta' and item.get('encrypted_delta'):
                await decrypt(item)
                reference['delta_events'] += 1
            elif item.get('event') == 'done':
                reference['done'] = True
                reference['reported_output_tokens'] = item.get('output_tokens')
            elif item.get('event') == 'error':
                reference['error_code'] = item.get('code')
        reference_end = await idle('after_reference')
        reference['elapsed_ms'] = (time.monotonic() - reference_started) * 1000
        reference['decode_batch_calls'] = reference_end['batch_calls'] - before['batch_calls']
        reference['decode_batch_rows'] = reference_end['batch_rows'] - before['batch_rows']
        reference['scalar_decode_calls'] = reference_end['scalar_decode_calls'] - before['scalar_decode_calls']
        check('reference_stream_reached_32_token_limit', reference['done'] and reference['reported_output_tokens'] == 32 and 'error_code' not in reference)
        sid = c.new_session(prefix='security-cancel-' + report['run_id'])
        report['own_session_id'] = sid
        row = {'delta_events': 0, 'delta_events_after_cancel_response': 0, 'decrypted_characters': 0,
               'reported_output_tokens': None, 'token_count_note': 'Delta events are not token counts; cancelled EOF has no usage.',
               'termination': 'not_started', 'max_new_tokens': 32}
        report['cancelled_stream'] = row
        stream = await prepare(sid, prompt, 32)
        own_started = True
        row['termination'] = 'in_progress'
        async for item in stream:
            kind = item.get('event')
            if kind == 'delta' and item.get('encrypted_delta'):
                row['delta_events'] += 1
                row['decrypted_characters'] += await decrypt(item)
                if cancel_attempted:
                    row['delta_events_after_cancel_response'] += 1
                else:
                    row['first_delta_monotonic'] = time.monotonic()
                    check('cancel_api_accepted_own_session', await cancel_own('first_delta'))
                    row['cancel_response_monotonic'] = time.monotonic()
            elif kind == 'done':
                row['termination'] = 'normal_done'
                row['reported_output_tokens'] = item.get('output_tokens')
            elif kind == 'error':
                row['termination'] = 'sdk_error_event'
                row['error_code'] = item.get('code')
        own_terminated = True
        if row['termination'] == 'in_progress':
            row['termination'] = 'eof_without_done'
        row['stream_end_monotonic'] = time.monotonic()
        check('cancel_triggered_after_authenticated_delta', cancel_attempted and row['delta_events'] > 0)
        check('stream_ended_without_normal_completion_or_error', row['termination'] == 'eof_without_done')
        cancel_end = await idle('after_cancel')
        row['decode_batch_calls'] = cancel_end['batch_calls'] - reference_end['batch_calls']
        row['decode_batch_rows'] = cancel_end['batch_rows'] - reference_end['batch_rows']
        row['scalar_decode_calls'] = cancel_end['scalar_decode_calls'] - reference_end['scalar_decode_calls']
        row['idle_after_first_delta_ms'] = (time.monotonic() - row.get('first_delta_monotonic', time.monotonic())) * 1000
        row['decode_batches_after_cancel_response'] = cancel_end['batch_calls'] - report.get('metrics_after_cancel_response', cancel_end)['batch_calls']
        # Under isolated batch=1, a reduction of >=8 decode calls and <=75%
        # of the full deterministic reference distinguishes early backend stop
        # from mere stream truncation followed by natural completion.
        ref_calls = reference['decode_batch_calls'] + reference['scalar_decode_calls']
        actual_calls = row['decode_batch_calls'] + row['scalar_decode_calls']
        report['backend_cancel_proven'] = bool(
            reference['done'] and reference['reported_output_tokens'] == 32
            and row['termination'] == 'eof_without_done'
            and report.get('metrics_before_cancel', {}).get('active', 0) > 0
            and ref_calls >= 24 and actual_calls <= ref_calls * .75
            and ref_calls - actual_calls >= 8 and row['idle_after_first_delta_ms'] <= 5000
            and cancel_end['requests'] - reference_end['requests'] == 1)
        check('backend_early_stop_distinguished_from_natural_completion', report['backend_cancel_proven'])
        check('backend_idle_after_cancel', True)

        recovery = {'delta_events': 0, 'done': False, 'reported_output_tokens': None}
        report['recovery'] = recovery
        stream = await prepare(c.new_session(prefix='security-recovery-' + report['run_id']), 'Reply OK.', 4)
        async for item in stream:
            if item.get('event') == 'delta' and item.get('encrypted_delta'):
                await decrypt(item)
                recovery['delta_events'] += 1
            elif item.get('event') == 'done':
                recovery['done'] = True
                recovery['reported_output_tokens'] = item.get('output_tokens')
            elif item.get('event') == 'error':
                recovery['error_code'] = item.get('code')
        check('recovery_authenticated_stream_completed', recovery['done'] and recovery['delta_events'] > 0 and 'error_code' not in recovery)
        after = await idle('after_recovery')
        check('backend_idle_after_recovery', True)
        delta = after['requests'] - before['requests']
        report['backend_request_delta'] = delta
        check('exactly_three_backend_requests', delta == 3)
    finally:
        # Do not touch any other session, process, key, policy or source file.
        if own_started and not own_terminated and not cancel_attempted:
            try:
                await cancel_own('cleanup_own_unfinished_session')
            except Exception as exc:
                report['cleanup_cancel_error_type'] = type(exc).__name__
        if c is not None:
            owned_key = key if key is not None else getattr(c, 'dek_id', None)
            if owned_key is not None:
                removed = c.remove_dek(owned_key) == 0
                try:
                    sdk.CryptoUtils.get_dek(owned_key)
                    absent = False
                except (ValueError, KeyError):
                    absent = True
                check('own_test_key_removed', removed and absent)
            await c.close_connection()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--directory', required=True)
    p.add_argument('--client-dir', default='/root/client')
    p.add_argument('--base-url', required=True)
    p.add_argument('--metrics-url', required=True)
    args = p.parse_args()
    report = {'run_id': secrets.token_hex(10), 'tests': [], 'passed': False,
              'scope': 'own-session cancellation, observed stream EOF, aggregate backend idle and recovery',
              'backend_cancel_proven': False,
              'limitations': 'Cancel handler discards worker abort outcome; no device memory wiping or exact cancelled token count claim.'}
    logging.disable(logging.CRITICAL)
    with open(os.devnull, 'w') as sink, contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
        try:
            asyncio.run(asyncio.wait_for(run(args, report), timeout=130))
        except Exception as exc:
            report['error_type'] = type(exc).__name__
            if report.get('cancelled_stream', {}).get('termination') == 'in_progress':
                report['cancelled_stream']['termination'] = 'timeout' if isinstance(exc, TimeoutError) else 'exception'
    report['passed'] = bool(report['tests']) and not report.get('error_type') and not report.get('blocked') and all(x['passed'] for x in report['tests'])
    with (Path(args.directory) / 'cancel_result.json').open('x', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    print(json.dumps(report))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
