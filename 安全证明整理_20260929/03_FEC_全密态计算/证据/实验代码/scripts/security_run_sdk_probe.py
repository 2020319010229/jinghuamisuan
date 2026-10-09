import argparse
import json
from pathlib import Path
import shlex
import time
from security_remote import Remote, credentials

def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--output-dir',type=Path,required=True)
    parser.add_argument('--replay-controls',action='store_true')
    parser.add_argument('--base-url')
    parser.add_argument('--client-dir',default='/root/client')
    parser.add_argument('--metrics-url')
    parser.add_argument('--save-replay',action='store_true')
    args=parser.parse_args(); args.output_dir.mkdir(parents=True,exist_ok=False)
    r=None; report={'started_ns':time.time_ns()}
    try:
        r=Remote()
        result=r.run('host','mktemp -d /tmp/otp-security-sdk-20260916.XXXXXX')
        directory=result['stdout'].strip()
        if result['exit_code'] or not directory.startswith('/tmp/otp-security-sdk-20260916.'):
            raise RuntimeError('Unexpected temporary path')
        report['directory']=directory
        r.put('host',Path(__file__).with_name('security_sdk_probe.py'),directory+'/security_sdk_probe.py')
        command='timeout 120 python3 '+shlex.quote(directory+'/security_sdk_probe.py')+' --directory '+shlex.quote(directory)+' --base-url '+shlex.quote(args.base_url or 'http://'+credentials.CVM+':8101')+' --client-dir '+shlex.quote(args.client_dir)
        if args.metrics_url: command+=' --metrics-url '+shlex.quote(args.metrics_url)
        if args.replay_controls: command+=' --replay-controls'
        if args.save_replay: command+=' --save-replay'
        report['execution']=r.run('host',command,timeout=130)
        r.get('host',directory+'/sdk_result.json',args.output_dir/'sdk_result.json')
        if args.save_replay:
            r.get('host',directory+'/synthetic_replay_request.json',args.output_dir/'synthetic_replay_request.json')
        try:
            r.get('host',directory+'/experiment_certificate.der',args.output_dir/'experiment_certificate.der')
        except FileNotFoundError:
            report['certificate_saved']=False
    except Exception as exc:
        report['error_type']=type(exc).__name__
    finally:
        if r: r.close()
        report['finished_ns']=time.time_ns()
        with (args.output_dir/'orchestration.json').open('x',encoding='utf-8') as f:
            json.dump(report,f,ensure_ascii=False,indent=2)
        print(json.dumps({'directory':str(args.output_dir),'error_type':report.get('error_type'),'exit':report.get('execution',{}).get('exit_code')}))

if __name__=='__main__': main()
