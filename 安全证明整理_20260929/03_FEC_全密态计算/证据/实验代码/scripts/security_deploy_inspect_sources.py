"""Read startup/source metadata without printing .env or secret environment values."""
import argparse
import json
from pathlib import Path
import shlex
import time
from security_remote import Remote


def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    r=Remote();out={'started_ns':time.time_ns()}
    try:
        raw=r.run('cvm','docker inspect cvm-server')
        item=json.loads(raw['stdout'])[0]
        out['compose_labels']={k:v for k,v in item['Config'].get('Labels',{}).items() if k.startswith('com.docker.compose.')}
        out['ports']=item['HostConfig']['PortBindings']
        for name in ('server.py','cvm_env.py','storage_paths.py','dek_crypto.py'):
            out[name]=r.run('cvm','docker exec cvm-server cat '+shlex.quote('/opt/cvm/cvm_server/'+name))
        out['tools']=r.run('cvm','docker compose version; docker exec cvm-server python3 -c '+shlex.quote('import importlib.util,json; print(json.dumps({n:importlib.util.find_spec(n) is not None for n in ["ecies","keyring","flask","cryptography","gmssl"]}))'))
    finally:
        r.close();out['finished_ns']=time.time_ns()
        a.output.parent.mkdir(parents=True,exist_ok=True)
        with a.output.open('x',encoding='utf-8') as f:json.dump(out,f,ensure_ascii=False,indent=2)
        print(json.dumps(out,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
