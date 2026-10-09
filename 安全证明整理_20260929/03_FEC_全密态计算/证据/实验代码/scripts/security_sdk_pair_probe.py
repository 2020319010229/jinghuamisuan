"""Four short synthetic SDK requests: two serial references, then two concurrent.
Checks response consistency and cross-key authentication, not full tenant isolation.
"""
import argparse
import asyncio
import hashlib
import json
import logging
from pathlib import Path
import secrets
import sys
import time
import urllib.request
from urllib.parse import urlparse

async def run(args,report):
    sys.path.insert(0,'/root/client')
    from client import Client
    from utils.kunpeng_attestation import is_remote_attestation_enabled
    if not is_remote_attestation_enabled():
        raise RuntimeError('Attestation disabled; test refused')
    clients=[]; ids=[]; first_wire={}
    server=urlparse(args.base_url).hostname
    def metrics():
        with urllib.request.urlopen('http://'+server+':8020/metrics',timeout=5) as response:
            return json.loads(response.read())
    report['before']=metrics()
    if report['before'].get('active') or report['before'].get('queued'):
        report['blocked']='Service busy before experiment'; return
    try:
        for i in range(2):
            c=Client(args.base_url,model='qwen3.5-35b',max_new_tokens=16,temperature=0.0,top_p=1.0)
            clients.append(c)
            status,key_id=await c.env_init(str(Path(args.directory)/('cert_'+str(i)+'.der')),challenge_hex=secrets.token_hex(32))
            if status!=0 or key_id is None or not c.connected:
                raise RuntimeError('SDK initialization rejected')
            ids.append(key_id)
            with (Path(args.directory)/('test_dek_ownership_'+str(i)+'.json')).open('x') as f:
                json.dump({'run_id':report['run_id'],'test_dek_id':key_id,'client_index':i},f)
        prompts=['Compute 2 plus 3. Answer only the number.', 'Translate the word cat into French. Answer only the translated word.']
        report['synthetic_prompts']=prompts
        async def one(i,label):
            c=clients[i]; key_id=ids[i]
            session=c.new_session(prefix='security-'+report['run_id']+'-'+label+'-'+str(i))
            encoded=await c.Plain_content2Encrypted_content(plain_inputdata=[{'role':'system','plain_content':None},{'role':'user','plain_content':prompts[i]}],encryption_key_id=key_id)
            if encoded.get('status')!='succeeded': raise RuntimeError('Encryption rejected')
            stream=await c.Encryption_Generation(session_id=session,encryption_data=encoded['data']['encryption_data'],
                enable_web_search=False,cache_enable=False,model='qwen3.5-35b',max_new_tokens=16,
                temperature=0.0,top_p=1.0,stop='',presence_penalty=0.0,frequency_penalty=0.0,include_reasoning=False,stream=True)
            row={'client':i,'phase':label,'session':session,'start_ns':time.monotonic_ns(),'deltas':0,'done':False}; parts=[]
            async for item in stream:
                if item.get('event')=='delta' and item.get('encrypted_delta'):
                    wire=item['encrypted_delta']
                    if (label,i) not in first_wire: first_wire[(label,i)]=wire
                    value=await c.Encrypted_generation_res2Plain_generation_res(wire,key_id)
                    if value.get('status')!='succeeded': raise RuntimeError('Decrypt rejected')
                    parts.append((value.get('data') or {}).get('plain_generation_outputdata',''))
                    row['deltas']+=1
                elif item.get('event')=='done': row['done']=True; break
                elif item.get('event')=='error': raise RuntimeError('Stream error')
            row['end_ns']=time.monotonic_ns(); row['synthetic_output']=''.join(parts)
            row['output_sha256']=hashlib.sha256(row['synthetic_output'].encode()).hexdigest()
            return row
        report['serial']=[await one(i,'serial') for i in range(2)]
        report['concurrent']=await asyncio.gather(*(one(i,'concurrent') for i in range(2)))
        report['tests']=[]
        def check(name,value): report['tests'].append({'name':name,'passed':bool(value)})
        check('all_four_streams_done_and_decrypted',all(x['done'] and x['deltas']>0 for x in report['serial']+report['concurrent']))
        for i in range(2):
            check('client_'+str(i)+'_concurrent_matches_serial',report['serial'][i]['output_sha256']==report['concurrent'][i]['output_sha256'])
            for phase in ('serial','concurrent'):
                wrong=await clients[1-i].Encrypted_generation_res2Plain_generation_res(first_wire[(phase,i)],ids[1-i])
                check(phase+'_client_'+str(i)+'_response_rejects_other_key',wrong.get('status')!='succeeded')
        check('reference_outputs_distinguishable',report['serial'][0]['output_sha256']!=report['serial'][1]['output_sha256'])
        a,b=report['concurrent']
        report['concurrent_interval_overlap_ms']=max(0,min(a['end_ns'],b['end_ns'])-max(a['start_ns'],b['start_ns']))/1e6
        check('client_request_intervals_overlap',report['concurrent_interval_overlap_ms']>0)
        report['after']=metrics()
        report['backend_request_delta']=report['after']['requests']-report['before']['requests']
        check('exactly_four_backend_requests',report['backend_request_delta']==4)
        check('backend_idle_after',report['after']['active']==0 and report['after']['queued']==0)
    finally:
        report['own_dek_cleanup']=[]
        for c in clients:
            key_id=getattr(c,'dek_id',None)
            if key_id is not None: report['own_dek_cleanup'].append(c.remove_dek(key_id))
            await c.close_connection()

def main():
    p=argparse.ArgumentParser(); p.add_argument('--directory',required=True); p.add_argument('--base-url',required=True); a=p.parse_args()
    logging.disable(logging.CRITICAL)
    report={'run_id':secrets.token_hex(10),'scope':'two clients in one host process, distinct DEKs and sessions; not OS tenant isolation'}
    try: asyncio.run(asyncio.wait_for(run(a,report),timeout=180))
    except Exception as exc: report['error_type']=type(exc).__name__
    with (Path(a.directory)/'pair_result.json').open('x',encoding='utf-8') as f: json.dump(report,f,ensure_ascii=False,indent=2)
    print(json.dumps({'tests':report.get('tests'),'error_type':report.get('error_type')}))

if __name__=='__main__': main()
