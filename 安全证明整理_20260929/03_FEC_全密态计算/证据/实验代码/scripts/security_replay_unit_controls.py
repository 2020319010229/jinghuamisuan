"""Offline timestamp/replay checks in an isolated module, no live cache changes."""
import argparse
import importlib.util
import json
from pathlib import Path
import time

def main():
    p=argparse.ArgumentParser(); p.add_argument('--source',type=Path,required=True); p.add_argument('--output',type=Path,required=True); a=p.parse_args()
    spec=importlib.util.spec_from_file_location('isolated_replay_test',a.source)
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    report={'scope':'isolated replay guard only; no inference endpoint called','tests':[]}
    now=time.time()
    cases=[('fresh',now,'same',True),('exact_duplicate',now,'same',False),
           ('same_timestamp_new_request_id',now,'different',False),
           ('stale',now-1000,'stale',False),('future',now+1000,'future',False),
           ('nan_number',float('nan'),'nan_number',False),('nan_string','NaN','nan_string',False),
           ('positive_infinity',float('inf'),'inf',False),('boolean',True,'bool',False),('missing',None,'missing',False)]
    for name,ts,rid,expected in cases:
        accepted,error=module.check_internal_timestamp_and_replay({'timestamp':ts},rid)
        report['tests'].append({'name':name,'accepted':accepted,'expected_accept':expected,'passed':accepted==expected,'error':error})
    report['limitation']='Changing request_id case tests a stronger ciphertext-replay requirement than this guard alone implements; end-to-end handling must be checked separately.'
    report['passed']=sum(t['passed'] for t in report['tests']); report['total']=len(report['tests'])
    with a.output.open('x',encoding='utf-8') as f: json.dump(report,f,ensure_ascii=False,indent=2)
    print(json.dumps({'passed':report['passed'],'total':report['total']}))

if __name__=='__main__': main()
