"""Stage an explicit source whitelist and run loopback-only cancellation chain."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import shlex
import tarfile
import tempfile
from security_remote import Remote


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--output-dir',type=Path,required=True)
    args=parser.parse_args();args.output_dir.mkdir(parents=True,exist_ok=False)
    project=Path(__file__).resolve().parents[1]
    candidate=project/'security_fixes/20260917_cancel'
    mapping={name:candidate/name for name in ('engine/serve35_cb.c','engine/otp_cancel.h','engine/tests/model35.h','engine/tests/mock_server.cpp','tests/test_cancel_chain.py')}
    mapping.update({'tee_gateway.py':candidate/'gateway/tee_gateway.py','otp_cancel_registry.py':candidate/'gateway/otp_cancel_registry.py','otp_cancel_auth.py':candidate/'protocol/otp_cancel_auth.py','tee_crypto.py':project/'tee_crypto.py'})
    snapshot={name:path.read_bytes() for name,path in mapping.items()}
    report={'scope':'isolated loopback real HTTP gateway-to-mocked-model engine; no deployment', 'sha256':{name:hashlib.sha256(data).hexdigest() for name,data in snapshot.items()}}
    remote=None
    try:
        remote=Remote()
        def run(key,cmd,timeout=60):
            result=remote.run('cvm',cmd,timeout=timeout);report[key]=result;return result
        stage=run('create_stage','mktemp -d /tmp/otp-security-cancel-chain-stage.XXXXXX')['stdout'].strip()
        dest=run('create_container_dir','docker exec otp-c35-cb mktemp -d /tmp/otp-security-cancel-chain-test.XXXXXX')['stdout'].strip()
        if not stage.startswith('/tmp/otp-security-cancel-chain-stage.') or not dest.startswith('/tmp/otp-security-cancel-chain-test.'):
            raise RuntimeError('Unexpected temporary path')
        report.update(staging=stage,container_directory=dest)
        with tempfile.TemporaryDirectory(prefix='otp-cancel-chain-') as local:
            bundle=Path(local)/'chain.tar'
            with tarfile.open(bundle,'w') as tar:
                for name,data in snapshot.items():
                    info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o600;tar.addfile(info,io.BytesIO(data))
            remote.put('cvm',bundle,stage+'/chain.tar')
        if run('copy','docker cp '+shlex.quote(stage+'/chain.tar')+' '+shlex.quote('otp-c35-cb:'+dest+'/chain.tar'))['exit_code']:
            raise RuntimeError('Copy failed')
        def inside(key,cmd,timeout=60):
            return run(key,'docker exec otp-c35-cb sh -c '+shlex.quote('cd '+shlex.quote(dest)+' && '+cmd),timeout)
        if inside('extract','tar -xf chain.tar')['exit_code']:
            raise RuntimeError('Extract failed')
        if inside('compile','timeout 45 g++ -std=c++17 -O1 -g -Wall -Wextra -pthread -Iengine/tests engine/tests/mock_server.cpp -o mock-engine')['exit_code']:
            raise RuntimeError('Compile failed')
        report['execution']=inside('test','timeout --signal=TERM --kill-after=10 65 python3 tests/test_cancel_chain.py --output chain.json',timeout=85)
        for name in ('chain.json','engine.log','gateway.log'):
            if run('retrieve_'+name,'docker cp '+shlex.quote('otp-c35-cb:'+dest+'/'+name)+' '+shlex.quote(stage+'/'+name))['exit_code']:
                raise RuntimeError('Result copy failed')
            remote.get('cvm',stage+'/'+name,args.output_dir/name)
        report['chain']=json.loads((args.output_dir/'chain.json').read_text(encoding='utf-8'))
    except Exception as exc:
        report['error_type']=type(exc).__name__
    finally:
        if remote:
            remote.close()
        with (args.output_dir/'result.json').open('x',encoding='utf-8') as out:
            json.dump(report,out,ensure_ascii=False,indent=2)
        print(json.dumps({'compile':report.get('compile',{}).get('exit_code'),'test':report.get('test',{}).get('exit_code'),'passed':report.get('chain',{}).get('passed'),'error_type':report.get('error_type')}))
    return 0 if report.get('chain',{}).get('passed') else 1


if __name__=='__main__':
    raise SystemExit(main())
