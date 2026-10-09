import argparse
import json
from pathlib import Path
import shlex
from security_remote import Remote

def main():
    p=argparse.ArgumentParser(); p.add_argument('--input',type=Path,action='append',required=True); p.add_argument('--output-dir',type=Path,required=True); a=p.parse_args()
    a.output_dir.mkdir(parents=True,exist_ok=False); r=None; report={}
    try:
        r=Remote(); result=r.run('host','mktemp -d /tmp/otp-security-key-cleanup-20260916.XXXXXX'); directory=result['stdout'].strip()
        if result['exit_code'] or not directory.startswith('/tmp/otp-security-key-cleanup-20260916.'): raise RuntimeError('Unexpected temporary path')
        report['directory']=directory
        r.put('host',Path(__file__).with_name('security_test_key_cleanup.py'),directory+'/security_test_key_cleanup.py')
        inputs=[]
        for i,source in enumerate(a.input):
            remote=directory+'/input_'+str(i)+'.json'; r.put('host',source,remote); inputs.extend(['--input',remote])
        command='timeout 30 python3 '+shlex.quote(directory+'/security_test_key_cleanup.py')+' '+' '.join(shlex.quote(x) for x in inputs)+' --output '+shlex.quote(directory+'/cleanup.json')
        report['execution']=r.run('host',command)
        if report['execution']['exit_code']==0:r.get('host',directory+'/cleanup.json',a.output_dir/'cleanup.json')
    except Exception as exc:report['error_type']=type(exc).__name__
    finally:
        if r:r.close()
        with (a.output_dir/'orchestration.json').open('x',encoding='utf-8') as f:json.dump(report,f,ensure_ascii=False,indent=2)
        print(json.dumps({'directory':str(a.output_dir),'error_type':report.get('error_type')}))

if __name__=='__main__':main()
