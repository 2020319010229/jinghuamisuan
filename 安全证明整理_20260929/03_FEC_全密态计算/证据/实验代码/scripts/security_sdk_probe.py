#!/usr/bin/env python3
"""Run one synthetic request through the unchanged installed SDK policy.

Does not export bearer headers or DEK material. Only public attestation evidence,
synthetic text, hashes, and event times are recorded. No production .env changes.
"""
import argparse
import asyncio
import hashlib
import http.client
import json
import logging
import os
from pathlib import Path
import secrets
import select
import socket
import sys
import time
import urllib.request
import urllib.error
from urllib.parse import urlparse


async def experiment(args, report):
    sys.path.insert(0,args.client_dir)
    import client as sdk
    from utils.kunpeng_attestation import is_remote_attestation_enabled, get_cvm_tee_type, resolve_env_value
    def event(name, **extra):
        report['events'].append({'name':name,'utc_ns':time.time_ns(),'monotonic_ns':time.monotonic_ns(),**extra})
    report['policy']={'remote_attestation_enabled':is_remote_attestation_enabled(), 'tee_type':get_cvm_tee_type()}
    for key in ('KUNPENG_ROOT_CERT','KUNPENG_SUB_CERT','KUNPENG_IMAGE_REF_JSON','KUNPENG_SOFTWARE_COMPONENTS_JSON'):
        value=resolve_env_value(key)
        path=Path(value) if value else None
        report['policy'][key]={'configured':bool(value),'file_exists':bool(path and path.is_file())}
        if path and path.is_file():
            report['policy'][key]['sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
    report['policy']['measurement_reference_configured']=bool(resolve_env_value('KUNPENG_CVM_MEASUREMENT'))
    report['policy']['KUNPENG_REQUIRE_COSE']=resolve_env_value('KUNPENG_REQUIRE_COSE','1')
    report['sdk_hashes']={}
    for name in ('client.py','utils/kunpeng_attestation.py','utils/request_auth.py','utils/crypto_utils.py','utils/gm_crypto.py','http_auth.py'):
        path=Path(args.client_dir)/name
        if path.exists():
            report['sdk_hashes'][name]=hashlib.sha256(path.read_bytes()).hexdigest()
    original=urllib.request.urlopen
    generation_bodies=[]
    class ResponseProxy:
        def __init__(self,response,label):
            self.response,self.label=response,label
        def __enter__(self):
            self.response.__enter__(); return self
        def __exit__(self,*params):
            return self.response.__exit__(*params)
        def __getattr__(self,name):
            return getattr(self.response,name)
        def __iter__(self):
            return iter(self.response)
        def read(self,*params):
            value=self.response.read(*params)
            if self.label=='certificate':
                doc=json.loads(value)
                data=doc.get('data') or {}
                report['public_attestation_response']={key:data[key] for key in ('certificate_pem','kunpeng_token','kunpeng_dev_cert','tdx_quote') if key in data}
                event('certificate_received',http_status=self.response.status,bytes=len(value))
            return value
    def traced_urlopen(req,*params,**kwargs):
        url=req.full_url if isinstance(req,urllib.request.Request) else str(req)
        label='certificate' if '/internal/cpu-tee/certificate' in url else 'generation'
        body=getattr(req,'data',None)
        if label=='generation' and body:
            generation_bodies.append(body)
        if args.capture and isinstance(req,urllib.request.Request):
            req.add_header('X-Experiment-ID',report['wire_control_marker'])
        event(label+'_http_submit',body_bytes=len(body) if body else 0,
              body_sha256=hashlib.sha256(body).hexdigest() if body else None)
        response=original(req,*params,**kwargs)
        event(label+'_http_headers',http_status=response.status)
        return ResponseProxy(response,label)
    urllib.request.urlopen=traced_urlopen
    client=None; capture=None; reserved=[]; original_connect=http.client.HTTPConnection.connect
    try:
        client=sdk.Client(args.base_url,model='qwen3.5-35b',max_new_tokens=4,temperature=0.0,top_p=1.0)
        report['auth_header_configured']=bool(getattr(client,'saas_key',None))
        if not report['policy']['remote_attestation_enabled']:
            report['blocked']='Existing SDK policy disables attestation; no inference attempted, policy unchanged.'
            return
        if args.capture:
            if report['auth_header_configured']:
                raise RuntimeError('Raw SDK capture refused because bearer authentication is configured')
            from security_wire_probe import Capture
            target=urlparse(args.base_url)
            if target.scheme!='http' or target.port!=8101:
                raise RuntimeError('Capture only implemented for observed HTTP 8101 protocol')
            route=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); route.connect((target.hostname,target.port))
            peer=route.getsockname()[0]; route.close()
            for _ in range(2):
                s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.bind((peer,0)); s.settimeout(90); reserved.append(s)
            ports=[s.getsockname()[1] for s in reserved]
            pool=iter(reserved)
            def connect(con):
                if con.host==target.hostname and con.port==target.port:
                    s=next(pool); s.connect((target.hostname,target.port)); con.sock=s
                else:
                    return original_connect(con)
            http.client.HTTPConnection.connect=connect
            capture=Capture(Path(args.directory)/'host.pcap',peer,target.hostname,ports,target.port)
            capture.start()
            report['wire_control_marker']='OTPSEC_SDK_HEADER_'+report['run_id']
            print(json.dumps({'ready':True,'peer':peer,'ports':ports}),flush=True)
            if not select.select([sys.stdin],[],[],20)[0] or sys.stdin.readline().strip()!='go':
                raise RuntimeError('No capture readiness confirmation')
        challenge=secrets.token_hex(32)
        report['fresh_challenge_hex']=challenge
        event('identity_verification_start')
        status,dek_id=await client.env_init(str(Path(args.directory)/'experiment_certificate.der'),challenge_hex=challenge)
        event('identity_verification_end')
        report['initialization']={'status':status,'connected':bool(client.connected),'dek_created':dek_id is not None}
        if status != 0 or dek_id is None or not client.connected:
            report['blocked']='Fresh-challenge initialization rejected; inference not attempted.'
            return
        with (Path(args.directory)/'test_dek_ownership.json').open('x') as f:
            json.dump({'run_id':report['run_id'],'test_dek_id':dek_id,'utc_ns':time.time_ns()},f)
        prompt='OTPSEC_SDK_'+report['run_id']+' Reply OK.'
        report['synthetic_prompt']=prompt
        session_id=client.new_session(prefix='security-'+report['run_id'])
        report['session_id']=session_id
        event('prompt_encrypt_start')
        encrypted=await client.Plain_content2Encrypted_content(
            plain_inputdata=[{'role':'system','plain_content':None},{'role':'user','plain_content':prompt}],
            encryption_key_id=dek_id)
        event('prompt_encrypt_end')
        if encrypted.get('status')!='succeeded':
            raise RuntimeError('Prompt encryption rejected')
        event('generation_prepare_start')
        stream=await client.Encryption_Generation(session_id=session_id,
            encryption_data=encrypted['data']['encryption_data'],enable_web_search=False,cache_enable=False,
            model='qwen3.5-35b',max_new_tokens=4,temperature=0.0,top_p=1.0,stop='',
            presence_penalty=0.0,frequency_penalty=0.0,include_reasoning=False,stream=True)
        event('stream_iteration_start')
        plaintext=[]; deltas=0; done=False
        async for item in stream:
            kind=item.get('event')
            if kind=='delta':
                wire=item.get('encrypted_delta') or ''
                if not wire:
                    continue
                event('encrypted_delta_received',index=deltas,wire_sha256=hashlib.sha256(wire.encode()).hexdigest())
                if item.get('field')=='reasoning':
                    result=await client.Encrypted_reasoning_res2Plain_reasoning_res(wire,dek_id)
                    text=(result.get('data') or {}).get('plain_reasoning_outputdata','')
                else:
                    result=await client.Encrypted_generation_res2Plain_generation_res(wire,dek_id)
                    text=(result.get('data') or {}).get('plain_generation_outputdata','')
                if result.get('status')!='succeeded':
                    raise RuntimeError('Response authentication/decryption failed')
                event('delta_decrypted',index=deltas)
                deltas+=1; plaintext.append(text)
            elif kind=='done':
                done=True; report['done']=item; event('done_received'); break
            elif kind=='error':
                raise RuntimeError('SDK stream reported error')
        report['generation']={'decrypted_delta_count':deltas,'done_received':done,
                              'synthetic_output':''.join(plaintext),'passed':deltas>0 and done}
        if args.replay_controls and done and generation_bodies:
            transmitted=json.loads(generation_bodies[-1])
            if args.save_replay:
                replay_path=Path(args.directory)/'synthetic_replay_request.json'
                fd=os.open(replay_path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
                with os.fdopen(fd,'w',encoding='utf-8') as f:json.dump(transmitted,f,ensure_ascii=False)
                report['saved_replay_request']='synthetic encrypted request only; no plaintext DEK or auth headers'
            report['replay_controls']=[]
            target=urlparse(args.base_url)
            metrics_url=args.metrics_url or 'http://'+target.hostname+':8020/metrics'
            def metrics():
                with original(metrics_url,timeout=5) as response:
                    return json.loads(response.read())
            def send_control(req):
                try:
                    with original(req,timeout=20) as response:
                        return response.status,response.read(1024*1024)
                except urllib.error.HTTPError as exc:
                    return exc.code,exc.read(1024*1024)
            protocol_v2=(transmitted.get('params') or {}).get('request_auth',{}).get('version')==2
            report['request_auth_version']=2 if protocol_v2 else None
            controls=['exact_replay','same_ciphertext_changed_request_id']
            if protocol_v2: controls+=['changed_timestamp','changed_stream_flag','missing_authentication']
            for name in controls:
                body=json.loads(json.dumps(transmitted))
                if name=='same_ciphertext_changed_request_id': body['request_id']=secrets.token_hex(12)
                elif name=='changed_timestamp': body['params']['timestamp']=time.time()
                elif name=='changed_stream_flag': body['params']['stream']=not bool(body['params'].get('stream'))
                elif name=='missing_authentication': body['params'].pop('request_auth',None)
                before=metrics(); t0=time.monotonic_ns()
                req=urllib.request.Request(args.base_url+'/internal/generation',
                    json.dumps(body,separators=(',',':')).encode(),
                    headers=client._http_headers({'Content-Type':'application/json'}),method='POST')
                status,wire=await asyncio.wait_for(asyncio.to_thread(send_control,req),timeout=30)
                after=metrics()
                values=[json.loads(line) for line in wire.decode().splitlines() if line.strip()]
                completed=any((v.get('data') or {}).get('event')=='done' for v in values)
                code=values[0].get('code') if values else None
                message=str(values[0].get('message','')) if values else ''
                reason=('duplicate_cache' if '击中缓存' in message else 'timestamp_timeout' if 'timeout' in message else 'authentication_rejected' if 'request authentication' in message.lower() else 'other')
                request_age_s=time.time()-float((transmitted.get('params') or {}).get('timestamp',0))
                delta=int(after.get('requests',0))-int(before.get('requests',0))
                report['replay_controls'].append({'name':name,'http_status':status,'first_app_code':code,
                    'done_received':completed,'backend_request_delta':delta,'elapsed_ms':(time.monotonic_ns()-t0)/1e6,
                    'params_unchanged':body.get('params')==transmitted.get('params'),
                    'rejection_reason_category':reason,'request_age_s_client_clock':request_age_s,
                    'response_sha256':hashlib.sha256(wire).hexdigest(),
                    'passed':((code==5002 and reason=='duplicate_cache') if name=='exact_replay' or not protocol_v2 else (code!=0 and reason=='authentication_rejected')) and abs(request_age_s)<120 and not completed and delta==0})
    finally:
        urllib.request.urlopen=original
        http.client.HTTPConnection.connect=original_connect
        created_id=getattr(client,'dek_id',None)
        if created_id is not None:
            # Only remove the DEK created by this test client, never other keys.
            report['test_dek_cleanup_return']=client.remove_dek(created_id)
            try:
                sdk.CryptoUtils.get_dek(created_id)
                report['test_dek_absent_after_cleanup']=False
            except ValueError:
                report['test_dek_absent_after_cleanup']=True
        if client: await client.close_connection()
        for s in reserved: s.close()
        if capture: report['capture']=capture.stop()
        event('client_closed')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--directory',required=True)
    parser.add_argument('--client-dir',default='/root/client')
    parser.add_argument('--base-url',required=True)
    parser.add_argument('--metrics-url',help='Optional actual engine metrics URL for isolated service tests')
    parser.add_argument('--save-replay',action='store_true',help='Save own encrypted synthetic request for a restart replay check')
    parser.add_argument('--capture',action='store_true')
    parser.add_argument('--replay-controls',action='store_true')
    args=parser.parse_args()
    if args.capture and args.replay_controls:
        parser.error('--capture and --replay-controls are separate experiments; do not combine')
    report={'run_id':secrets.token_hex(12),'events':[],'scope':'current SDK policy with fresh challenge; not independent complete TEE validation'}
    # SDK debug output contains DEK bytes. Suppress every SDK logger for this run.
    logging.disable(logging.CRITICAL)
    try:
        asyncio.run(asyncio.wait_for(experiment(args,report),timeout=100))
    except Exception as exc:
        report['error_type']=type(exc).__name__
    with (Path(args.directory)/'sdk_result.json').open('x',encoding='utf-8') as f:
        json.dump(report,f,ensure_ascii=False,indent=2)
    print(json.dumps({'initialization':report.get('initialization'),'generation':report.get('generation'),
                      'blocked':report.get('blocked'),'error_type':report.get('error_type')}),flush=True)

if __name__=='__main__':
    main()
