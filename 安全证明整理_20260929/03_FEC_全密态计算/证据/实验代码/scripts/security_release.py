"""Upload or execute the narrowly scoped 20260917 release helper."""
import argparse
import json
from pathlib import Path
import shlex
import time
from security_remote import Remote,PROJECT,credentials

def main():
    p=argparse.ArgumentParser();p.add_argument('action',choices=['stage','apply-cvm','apply-sdk','apply-engine','images','sync-source']);p.add_argument('--state',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    report={'action':a.action,'started_ns':time.time_ns()};r=None
    try:
        r=Remote()
        if a.action=='stage':
            state={}
            for target,sub in [('host','sdk'),('cvm','server')]:
                res=r.run(target,'mktemp -d /tmp/otp-security-release-20260917.XXXXXX');directory=res['stdout'].strip()
                if res['exit_code'] or not directory.startswith('/tmp/otp-security-release-20260917.'):raise RuntimeError('Stage creation failed')
                state[target]=directory
                r.put(target,Path(__file__).with_name('security_release_remote.py'),directory+'/security_release_remote.py')
                root=PROJECT/'security_fixes/20260916'/sub
                for path in sorted(root.rglob('*.py')):
                    dest=directory+'/'+sub+'/'+path.relative_to(root).as_posix()
                    if r.run(target,'mkdir -p '+shlex.quote(dest.rsplit('/',1)[0]))['exit_code']:raise RuntimeError('Stage directory failed')
                    r.put(target,path,dest)
            a.state.parent.mkdir(parents=True,exist_ok=True)
            with a.state.open('x',encoding='utf-8') as f:json.dump(state,f,indent=2)
            commands=[('host','stage-sdk'),('cvm','stage-cvm')]
        else:
            state=json.loads(a.state.read_text());commands=[('host' if a.action=='apply-sdk' else 'cvm',a.action)]
        for target,action in commands:
            command='python3 '+shlex.quote(state[target]+'/security_release_remote.py')+' '+action+' --ip '+shlex.quote(credentials.CVM)
            result=r.run(target,command,timeout=240);report[action]=result
            if result['exit_code']:raise RuntimeError('Release phase failed: '+action)
    except Exception as exc:report['error_type']=type(exc).__name__
    finally:
        if r:r.close()
        report['finished_ns']=time.time_ns()
        with a.output.open('x',encoding='utf-8') as f:json.dump(report,f,indent=2)
        print(json.dumps(report,indent=2))
    return 1 if report.get('error_type') else 0

if __name__=='__main__':raise SystemExit(main())
