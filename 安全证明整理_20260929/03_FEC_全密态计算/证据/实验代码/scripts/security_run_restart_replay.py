"""Create an authenticated request, restart CVM service, prove durable rejection."""
import argparse
import json
from pathlib import Path
import shlex
import subprocess
import sys
import time
from security_remote import Remote,credentials

def main():
    p=argparse.ArgumentParser();p.add_argument('--output-dir',type=Path,required=True);a=p.parse_args();a.output_dir.mkdir(parents=True,exist_ok=False)
    out={};r=None
    try:
        probe=a.output_dir/'fresh_request'
        code=subprocess.call([sys.executable,str(Path(__file__).with_name('security_run_sdk_probe.py')),'--output-dir',str(probe),'--replay-controls','--save-replay'])
        d=json.loads((probe/'sdk_result.json').read_text(encoding='utf-8'))
        if code or d.get('error_type') or not d.get('generation',{}).get('passed') or len(d.get('replay_controls',[]))!=5 or not all(x['passed'] for x in d['replay_controls']):raise RuntimeError('Fresh request or controls failed')
        directory=json.loads((probe/'orchestration.json').read_text())['directory']
        r=Remote();out['before']=json.loads(r.run('cvm','docker inspect cvm-server')['stdout'])[0]['State']['StartedAt']
        metrics=r.run('cvm',"curl --noproxy '*' -fsS http://127.0.0.1:8020/metrics")
        m=json.loads(metrics['stdout'])
        if m['active'] or m['queued']:raise RuntimeError('Backend busy; restart refused')
        r.put('host',Path(__file__).with_name('security_restart_replay_probe.py'),directory+'/security_restart_replay_probe.py')
        restart=r.run('cvm','docker restart --time 20 cvm-server',timeout=40)
        out['restart_exit']=restart['exit_code']
        if restart['exit_code']:raise RuntimeError('Restart failed')
        for _ in range(10):
            health=r.run('cvm',"curl --noproxy '*' -fsS --max-time 2 -X POST -H 'Content-Type: application/json' -d '{}' http://127.0.0.1:8101/internal/health")
            if health['exit_code']==0:break
            time.sleep(1)
        else:raise RuntimeError('Service not ready')
        out['after']=json.loads(r.run('cvm','docker inspect cvm-server')['stdout'])[0]['State']['StartedAt']
        command='python3 '+shlex.quote(directory+'/security_restart_replay_probe.py')+' --request '+shlex.quote(directory+'/synthetic_replay_request.json')+' --base-url '+shlex.quote('http://'+credentials.CVM+':8101')+' --output '+shlex.quote(directory+'/restart_result.json')
        out['execution']=r.run('host',command,timeout=30)
        r.get('host',directory+'/restart_result.json',a.output_dir/'restart_result.json')
        result=json.loads((a.output_dir/'restart_result.json').read_text())
        out['passed']=out['before']!=out['after'] and result['passed'] and out['execution']['exit_code']==0
    except Exception as exc:out['error_type']=type(exc).__name__;out['passed']=False
    finally:
        if r:r.close()
        with (a.output_dir/'orchestration.json').open('x') as f:json.dump(out,f,indent=2)
        print(json.dumps(out,indent=2))
    return 0 if out.get('passed') else 1

if __name__=='__main__':raise SystemExit(main())
