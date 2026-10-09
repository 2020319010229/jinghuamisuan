"""Compile and execute test-only deterministic RNG harness in a fresh CVM directory."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import time
from security_remote import Remote, PROJECT

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--header',type=Path,help='Upload candidate header; default tests the untouched CVM header')
    parser.add_argument('--random-control',action='store_true',help='Also run existing test_otp_security with real getrandom')
    args=parser.parse_args()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x',encoding='utf-8') as f:
        r=Remote()
        report={'started_ns':time.time_ns(),'scope':'deterministic stub unit tests in isolated executable; no production entropy changes'}
        try:
            result=r.run('cvm','mktemp -d /tmp/otp-security-boundary-20260916.XXXXXX')
            directory=result['stdout'].strip()
            if result['exit_code'] or not directory.startswith('/tmp/otp-security-boundary-20260916.'):
                raise RuntimeError('Unexpected temporary path')
            report['directory']=directory
            report['prepare']=r.run('cvm','mkdir '+shlex.quote(directory+'/scripts'))
            if report['prepare']['exit_code']:
                raise RuntimeError('Cannot prepare test directory')
            if args.header:
                report['candidate_header_sha256']=hashlib.sha256(args.header.read_bytes()).hexdigest()
                r.put('cvm',args.header,directory+'/otp_rng.h')
            else:
                report['copy_header']=r.run('cvm','cp /data/otp_c35/otp_rng.h '+shlex.quote(directory+'/otp_rng.h'))
                if report['copy_header']['exit_code']:
                    raise RuntimeError('Cannot copy baseline header')
            r.put('cvm',PROJECT/'scripts/security_rng_boundary_test.c',directory+'/scripts/security_rng_boundary_test.c')
            report['source_hashes']=r.run('cvm','sha256sum '+shlex.quote(directory+'/otp_rng.h')+' '+shlex.quote(directory+'/scripts/security_rng_boundary_test.c'))
            report['compile']=r.run('cvm','cc -O2 -std=c11 -Wall -Wextra -Werror '+shlex.quote(directory+'/scripts/security_rng_boundary_test.c')+' -lm -o '+shlex.quote(directory+'/test'))
            if report['compile']['exit_code']==0:
                report['execution']=r.run('cvm','timeout 10 '+shlex.quote(directory+'/test'))
            if args.random_control:
                r.put('cvm',PROJECT/'test_otp_security.c',directory+'/test_otp_security.c')
                report['random_control_source_hash']=r.run('cvm','sha256sum '+shlex.quote(directory+'/test_otp_security.c'))
                report['random_compile']=r.run('cvm','cc -O2 -std=c11 -Wall -Wextra -Werror '+shlex.quote(directory+'/test_otp_security.c')+' -lm -o '+shlex.quote(directory+'/random_control'))
                if report['random_compile']['exit_code']==0:
                    report['random_execution']=r.run('cvm','timeout 15 '+shlex.quote(directory+'/random_control'))
        except Exception as exc:
            report['error_type']=type(exc).__name__
        finally:
            r.close()
            report['finished_ns']=time.time_ns()
            json.dump(report,f,ensure_ascii=False,indent=2)
        print(json.dumps({'output':str(args.output),'test_exit':report.get('execution',{}).get('exit_code'),'error_type':report.get('error_type')}))

if __name__=='__main__':
    main()
