"""Replay only this experiment's fresh synthetic ciphertext after service restart."""
import argparse
import json
import logging
from pathlib import Path
import sys
import time
import urllib.request
from urllib.parse import urlparse

def main():
    p=argparse.ArgumentParser();p.add_argument('--request',type=Path,required=True);p.add_argument('--base-url',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    logging.disable(logging.CRITICAL);sys.path.insert(0,'/root/client')
    from http_auth import resolve_saas_key,saas_auth_headers
    body=json.loads(a.request.read_text());metrics='http://'+urlparse(a.base_url).hostname+':8020/metrics'
    def read_metrics():
        with urllib.request.urlopen(metrics,timeout=5) as r:return json.load(r)
    before=read_metrics();age=time.time()-float(body['params']['timestamp'])
    headers={'Content-Type':'application/json',**saas_auth_headers(resolve_saas_key())}
    request=urllib.request.Request(a.base_url+'/internal/generation',json.dumps(body).encode(),headers=headers,method='POST')
    with urllib.request.urlopen(request,timeout=15) as r:
        status=r.status;rows=[json.loads(line) for line in r.read().decode().splitlines() if line.strip()]
    after=read_metrics();code=rows[0].get('code') if rows else None
    duplicate=bool(rows and '击中缓存' in str(rows[0].get('message','')))
    done=any((row.get('data') or {}).get('event')=='done' for row in rows)
    delta=after['requests']-before['requests']
    out={'http_status':status,'application_code':code,'duplicate_rejected':duplicate,'done_received':done,'request_age_s':age,'backend_request_delta':delta,'passed':status==200 and code==5002 and duplicate and not done and delta==0 and abs(age)<120}
    with a.output.open('x') as f:json.dump(out,f,indent=2)
    print(json.dumps(out));return 0 if out['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
