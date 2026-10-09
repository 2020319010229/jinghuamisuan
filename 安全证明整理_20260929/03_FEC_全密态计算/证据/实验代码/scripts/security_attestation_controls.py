"""Offline negative controls against a captured public attestation response.

Runs in a separate test process. No live endpoint, production policy or service
is changed. Strict mode is an explicit function argument, not an .env edit.
"""
import argparse
import hashlib
import json
import logging
from pathlib import Path
import sys
from cryptography import x509
from cryptography.hazmat.primitives import serialization

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--input',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--client-dir',default='/root/client')
    args=parser.parse_args()
    sys.path.insert(0,args.client_dir)
    from utils.crypto_utils import CryptoUtils
    from utils.gm_crypto import extract_spki_der_from_cert_der, sm3_digest
    from utils.kunpeng_attestation import verify_kunpeng_token, parse_cca_attestation_token, resolve_env_value
    logging.disable(logging.CRITICAL)
    doc=json.loads(args.input.read_text(encoding='utf-8'))
    evidence=doc['public_attestation_response']
    token=CryptoUtils.bytes_from_tdx_cert_or_quote_wire(evidence['kunpeng_token'])
    dev_cert=CryptoUtils.bytes_from_tdx_cert_or_quote_wire(evidence['kunpeng_dev_cert']) if evidence.get('kunpeng_dev_cert') else None
    der=x509.load_pem_x509_certificate(evidence['certificate_pem'].encode()).public_bytes(serialization.Encoding.DER)
    challenge=bytes.fromhex(doc['fresh_challenge_hex'])
    expected=sm3_digest(extract_spki_der_from_cert_der(der)+challenge)+challenge
    parsed=parse_cca_attestation_token(token)
    signature=parsed['cvm']['cose']['signature']
    report={'scope':'offline verification controls only, not a hardware quote authenticity verdict',
            'input_sha256':hashlib.sha256(args.input.read_bytes()).hexdigest(),
            'token_sha256':hashlib.sha256(token).hexdigest(),
            'current_require_cose':resolve_env_value('KUNPENG_REQUIRE_COSE','1'),
            'platform_token_present':parsed.get('platform') is not None,
            'device_certificate_present':bool(dev_cert),'tests':[]}
    def check(name, token_value, expected_accept, **kwargs):
        accepted,reason=verify_kunpeng_token(token_value,expected_challenge=kwargs.pop('expected_challenge',expected),
                                             dev_cert=kwargs.pop('dev_cert',dev_cert),**kwargs)
        report['tests'].append({'name':name,'accepted':bool(accepted),'expected_accept':expected_accept,
                                'passed':bool(accepted)==expected_accept,'reason':reason})
    check('captured_token_current_policy',token,True)
    check('wrong_fresh_challenge_rejected',token,False,expected_challenge=bytes([expected[0]^1])+expected[1:])
    check('wrong_measurement_rejected',token,False,measurement_hex='00'*48)
    check('captured_token_strict_cose',token,True,require_cose=True)
    if signature and token.count(signature)==1:
        offset=token.index(signature)+len(signature)-1
        mutated=bytearray(token); mutated[offset]^=1
        report['tamper']={'location':'last byte of CVM COSE signature','byte_offset':offset,
                          'sha256':hashlib.sha256(mutated).hexdigest()}
        check('tampered_cvm_signature_rejected_current_policy',bytes(mutated),False)
        check('tampered_cvm_signature_rejected_strict_cose',bytes(mutated),False,require_cose=True)
    else:
        report['tamper_not_executed']='Signature not uniquely located'
    check('missing_device_certificate_rejected',token,False,dev_cert=None)
    report['passed']=sum(t['passed'] for t in report['tests'])
    report['total']=len(report['tests'])
    with args.output.open('x',encoding='utf-8') as f:
        json.dump(report,f,ensure_ascii=False,indent=2)
    print(json.dumps({'passed':report['passed'],'total':report['total']}))

if __name__=='__main__': main()
