#!/usr/bin/env python3
"""Customer-only functional selfcheck. No SSH, backend metrics, or policy changes.

Copy this file and security_sdk_probe.py into the same directory.
"""
import argparse
import ast
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from urllib.parse import urlsplit


def validate_result(report):
    init = report.get('initialization', {})
    generation = report.get('generation', {})
    events = report.get('events', [])
    names = [event.get('name') for event in events]
    challenge = report.get('fresh_challenge_hex', '')
    checks = {
        'no_block_or_error': not any(key in report for key in ('blocked', 'error', 'error_type')),
        'attestation_enabled': report.get('policy', {}).get('remote_attestation_enabled') is True,
        'fresh_challenge': isinstance(challenge, str) and len(challenge) == 64 and all(c in '0123456789abcdef' for c in challenge),
        'initialized': type(init.get('status')) is int and init['status'] == 0 and init.get('connected') is True and init.get('dek_created') is True,
        'four_authenticated_deltas': generation.get('decrypted_delta_count') == 4 and names.count('delta_decrypted') == 4,
        'done': generation.get('done_received') is True and generation.get('passed') is True and names.count('done_received') == 1,
        'test_dek_removed': type(report.get('test_dek_cleanup_return')) is int and report['test_dek_cleanup_return'] == 0 and report.get('test_dek_absent_after_cleanup') is True,
        'client_closed': names.count('client_closed') == 1,
        'no_capture_or_replay': not any(key in report for key in ('capture', 'replay_controls', 'saved_replay_request')),
    }
    required = ('identity_verification_start', 'identity_verification_end', 'prompt_encrypt_start',
                'prompt_encrypt_end', 'generation_prepare_start', 'stream_iteration_start', 'done_received', 'client_closed')
    checks['event_order'] = all(names.count(name) == 1 for name in required)
    if checks['event_order']:
        positions = [names.index(name) for name in required]
        checks['event_order'] = positions == sorted(positions)
    return checks


def sdk_version_check(client_dir):
    auth_path = client_dir / 'utils/request_auth.py'
    client_path = client_dir / 'client.py'
    source = ast.parse(client_path.read_text(encoding='utf-8-sig'))
    imported = any(isinstance(node, ast.ImportFrom) and node.module == 'utils.request_auth'
                   and any(alias.name == 'sign_request' and alias.asname in (None, 'sign_request') for alias in node.names)
                   for node in ast.walk(source))
    called = any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'sign_request'
                 for node in ast.walk(source))
    if not imported or not called:
        raise ValueError('SDK request authentication integration absent')
    spec = importlib.util.spec_from_file_location('customer_request_auth_check', auth_path)
    module = importlib.util.module_from_spec(spec)
    # This executes the customer's installed module; all diagnostic output is suppressed.
    with open(os.devnull, 'w') as sink, contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
        spec.loader.exec_module(module)
        if not callable(getattr(module, 'sign_request', None)) or not callable(getattr(module, 'verify_request', None)):
            raise ValueError('Request authentication functions absent')
        synthetic_key = bytes(range(32))  # Public fixed test vector, never a service DEK.
        signed = module.sign_request({'timestamp': 1000.0, 'stream': True}, 'customer-local-test', synthetic_key)
        if signed.get('request_auth', {}).get('version') != 2:
            raise ValueError('Request authentication version is not 2')
        module.verify_request(signed, 'customer-local-test', synthetic_key, now=1000.0)
    return {'version': 2, 'local_sign_verify_pass': True,
            'client_sha256': hashlib.sha256(client_path.read_bytes()).hexdigest(),
            'request_auth_sha256': hashlib.sha256(auth_path.read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', required=True)
    parser.add_argument('--client-dir', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    target = urlsplit(args.base_url)
    if target.scheme not in ('http', 'https') or not target.hostname or target.username or target.password or target.query or target.fragment:
        parser.error('base-url must be an HTTP(S) endpoint without credentials, query, or fragment')
    client_dir = args.client_dir.resolve()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    report = {'started_ns': time.time_ns(), 'pass': False,
              'scope': 'customer SDK functional selfcheck; not formal security acceptance or complete trust-root validation'}
    try:
        probe = Path(__file__).resolve().with_name('security_sdk_probe.py')
        if not probe.is_file():
            raise FileNotFoundError('Companion security_sdk_probe.py required')
        report['request_auth'] = sdk_version_check(client_dir)
        report['entry_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        report['probe_sha256'] = hashlib.sha256(probe.read_bytes()).hexdigest()
        # Preserve SDK environment configuration. No replay/capture flag, SSH, or metrics access.
        # Discard console output because arbitrary SDK print statements may expose secrets.
        result = subprocess.run([sys.executable, str(probe), '--base-url', args.base_url,
                                 '--client-dir', str(client_dir), '--directory', str(output_dir)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=130)
        report['probe_exit'] = result.returncode
        data = json.loads((output_dir / 'sdk_result.json').read_text(encoding='utf-8'))
        report['checks'] = validate_result(data)
        report['pass'] = result.returncode == 0 and all(report['checks'].values())
    except Exception as exc:
        # Exception messages may contain endpoints or SDK material; record class only.
        report['error_type'] = type(exc).__name__
    report['finished_ns'] = time.time_ns()
    with (output_dir / 'customer_selfcheck.json').open('x', encoding='utf-8') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
    print(json.dumps({'pass': report['pass'], 'failed_checks': [k for k, v in report.get('checks', {}).items() if not v],
                      'error_type': report.get('error_type')}, ensure_ascii=False))
    return 0 if report['pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
