import argparse
import base64
import json
from pathlib import Path
import shlex
from security_remote import Remote

def main():
    p=argparse.ArgumentParser(); p.add_argument('--output',type=Path,required=True); a=p.parse_args()
    payload=base64.b64encode(Path(__file__).with_name('security_runtime_inspect.py').read_bytes()).decode()
    command='python3 -c '+shlex.quote("import base64; exec(compile(base64.b64decode('"+payload+"'),'<security-runtime-inspect>','exec'))")
    with a.output.open('x',encoding='utf-8') as f:
        r=Remote(); report={}
        try:
            for target in ('host','cvm'):
                raw=r.run(target,command,timeout=50)
                report[target]={'exit_code':raw['exit_code'],'stderr':raw['stderr']}
                if raw['exit_code']==0: report[target]['data']=json.loads(raw['stdout'])
                else: report[target]['stdout']=raw['stdout']
            report['backend_health']=r.run('cvm',"curl --noproxy '*' -sS --max-time 5 http://127.0.0.1:8020/healthz")
            report['backend_metrics']=r.run('cvm',"curl --noproxy '*' -sS --max-time 5 http://127.0.0.1:8020/metrics")
            report['image_source_inventory']=r.run('cvm',"docker exec otp-c35-cb sh -c 'ls -l /opt/otp35; find /opt/otp35 -maxdepth 3 -type f \\( -name \"*.c\" -o -name \"*.h\" -o -name \"*.py\" -o -iname \"*manifest*\" \\) | head -90'; docker exec cvm-server sh -c 'find /opt/cvm/cvm_server -maxdepth 2 -type f -name \"*.py\" | head -60'")
        finally:
            r.close(); json.dump(report,f,ensure_ascii=False,indent=2)
    print(str(a.output))

if __name__=='__main__': main()
