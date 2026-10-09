import argparse
import json
from pathlib import Path
import shlex
from security_remote import Remote

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--input',type=Path,required=True)
    parser.add_argument('--output-dir',type=Path,required=True)
    args=parser.parse_args(); args.output_dir.mkdir(parents=True,exist_ok=False)
    report={}; r=Remote()
    try:
        tmp=r.run('host','mktemp -d /tmp/otp-security-attestation-20260916.XXXXXX')
        directory=tmp['stdout'].strip()
        if tmp['exit_code'] or not directory.startswith('/tmp/otp-security-attestation-20260916.'):
            raise RuntimeError('Unexpected temporary path')
        report['directory']=directory
        r.put('host',args.input,directory+'/sdk_result.json')
        r.put('host',Path(__file__).with_name('security_attestation_controls.py'),directory+'/security_attestation_controls.py')
        report['execution']=r.run('host','timeout 30 python3 '+shlex.quote(directory+'/security_attestation_controls.py')+' --input '+shlex.quote(directory+'/sdk_result.json')+' --output '+shlex.quote(directory+'/controls.json'))
        if report['execution']['exit_code']==0:
            r.get('host',directory+'/controls.json',args.output_dir/'controls.json')
    except Exception as exc:
        report['error_type']=type(exc).__name__
    finally:
        r.close()
        with (args.output_dir/'orchestration.json').open('x',encoding='utf-8') as f: json.dump(report,f,ensure_ascii=False,indent=2)
        print(json.dumps({'directory':str(args.output_dir),'error_type':report.get('error_type'),'exit':report.get('execution',{}).get('exit_code')}))

if __name__=='__main__': main()
