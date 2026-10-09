"""Local synthetic-data checks; no server, TEE or device claims."""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from tee_crypto import REQUEST_AAD, RESPONSE_AAD, b64d, b64e, derive_key, open_json, public_bytes, seal_json


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    key_a = X25519PrivateKey.generate()
    key_b = X25519PrivateKey.generate()
    shared_a = derive_key(key_a, public_bytes(key_b.public_key()))
    shared_b = derive_key(key_b, public_bytes(key_a.public_key()))
    sample = {'request_id': 'local-synthetic', 'text': 'test marker'}
    envelope = seal_json(shared_a, sample, REQUEST_AAD)
    results = []

    def check(name, action):
        try:
            passed = bool(action())
            results.append({'test': name, 'passed': passed})
        except Exception as exc:
            results.append({'test': name, 'passed': False, 'error_type': type(exc).__name__})

    def rejects(key, item, aad):
        try:
            open_json(key, item, aad)
        except InvalidTag:
            return True
        return False

    check('key_agreement', lambda: shared_a == shared_b)
    check('request_roundtrip', lambda: open_json(shared_b, envelope, REQUEST_AAD) == sample)
    check('response_roundtrip', lambda: open_json(shared_a, seal_json(shared_b, sample, RESPONSE_AAD), RESPONSE_AAD) == sample)
    tampered = dict(envelope)
    raw = bytearray(b64d(tampered['ciphertext']))
    raw[0] ^= 1
    tampered['ciphertext'] = b64e(bytes(raw))
    check('tamper_rejected', lambda: rejects(shared_b, tampered, REQUEST_AAD))
    check('wrong_key_rejected', lambda: rejects(bytes(x ^ 1 for x in shared_b), envelope, REQUEST_AAD))
    check('wrong_aad_rejected', lambda: rejects(shared_b, envelope, RESPONSE_AAD))
    envelopes = [seal_json(shared_a, sample, REQUEST_AAD) for _ in range(1000)]
    check('nonce_sample_unique_1000', lambda: len({e['nonce'] for e in envelopes}) == 1000)
    report = {'scope': 'local transport crypto only; not OTP mask, replay, TEE or NPU verification',
              'utc_time': datetime.now(timezone.utc).isoformat(), 'tests': results,
              'passed': sum(x['passed'] for x in results), 'total': len(results)}
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'passed': report['passed'], 'total': report['total'], 'output': str(out)}))
    return 0 if report['passed'] == report['total'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
