import argparse
import json
from pathlib import Path
import shlex
from security_remote import Remote,credentials

def main():
    p=argparse.ArgumentParser(); p.add_argument('--output-dir',type=Path,required=True); a=p.parse_args()
    a.output_dir.mkdir(parents=True,exist_ok=False); r=None; report={}
    try:
        r=Remote()
        result=r.run('host','mktemp -d /tmp/otp-security-pair-20260916.XXXXXX')
        directory=result['stdout'].strip()
        if result['exit_code'] or not directory.startswith('/tmp/otp-security-pair-20260916.'):
            raise RuntimeError('Unexpected temporary path')
        report['directory']=directory
        r.put('host',Path(__file__).with_name('security_sdk_pair_probe.py'),directory+'/security_sdk_pair_probe.py')
        report['execution']=r.run('host','timeout 200 python3 '+shlex.quote(directory+'/security_sdk_pair_probe.py')+' --directory '+shlex.quote(directory)+' --base-url '+shlex.quote('http://'+credentials.CVM+':8101'),timeout=210)
        r.get('host',directory+'/pair_result.json',a.output_dir/'pair_result.json')
    except Exception as exc: report['error_type']=type(exc).__name__
    finally:
        if r: r.close()
        with (a.output_dir/'orchestration.json').open('x',encoding='utf-8') as f: json.dump(report,f,ensure_ascii=False,indent=2)
        print(json.dumps({'directory':str(a.output_dir),'error_type':report.get('error_type')}))

if __name__=='__main__': main()
