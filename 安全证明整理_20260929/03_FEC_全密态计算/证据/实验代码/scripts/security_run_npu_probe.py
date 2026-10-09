"""Build a tiny synthetic RNS probe in a new container directory, never deploy it."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import time
from security_remote import Remote,PROJECT

def main():
    p=argparse.ArgumentParser(); p.add_argument('--output-dir',type=Path,required=True); a=p.parse_args()
    a.output_dir.mkdir(parents=True,exist_ok=False); r=None; report={'started_ns':time.time_ns(),'scope':'independent synthetic NPU process; not production-process tracing or physical PCIe capture'}
    try:
        r=Remote()
        before=r.run('cvm',"curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8020/metrics")
        report['before']=json.loads(before['stdout'])
        if report['before'].get('active') or report['before'].get('queued'):
            raise RuntimeError('Backend busy; no NPU experiment started')
        tmp=r.run('cvm','mktemp -d /tmp/otp-security-npu-stage-20260916.XXXXXX'); stage=tmp['stdout'].strip()
        tmp2=r.run('cvm','docker exec otp-c35-cb mktemp -d /tmp/otp-security-npu-20260916.XXXXXX'); directory=tmp2['stdout'].strip()
        if tmp['exit_code'] or tmp2['exit_code'] or not stage.startswith('/tmp/otp-security-npu-stage-20260916.') or not directory.startswith('/tmp/otp-security-npu-20260916.'):
            raise RuntimeError('Unexpected temporary path')
        report['staging']=stage; report['container_directory']=directory
        frozen=PROJECT/'delivery/OTP35B_CB_V11_20260903'
        files=[frozen/n for n in ('q8_ops.c','q8_ops.h','st35.c','st35.h','otp_rng.h')]+[PROJECT/'scripts/security_npu_probe.cpp']
        report['source_sha256']={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in files}
        for f in files:r.put('cvm',f,stage+'/'+f.name)
        report['copy']=r.run('cvm','docker cp '+shlex.quote(stage+'/.')+' '+shlex.quote('otp-c35-cb:'+directory+'/'))
        if report['copy']['exit_code']: raise RuntimeError('Copy failed')
        prefix='docker exec otp-c35-cb sh -c '
        cann='/usr/local/Ascend/cann-9.1.0/aarch64-linux'
        command='cd '+shlex.quote(directory)+' && g++ -O2 -march=armv8.6-a+sve+i8mm+bf16 -std=c++17 -Wall -Wno-unused-function -Wno-deprecated-declarations -pthread -fopenmp -I'+cann+'/include -x c++ security_npu_probe.cpp q8_ops.c st35.c -o probe -L'+cann+'/lib64 -lascendcl -lnnopbase -lopapi -L/data/ascendc/build -lbdszblind -Wl,-rpath,/data/ascendc/build -Wl,--wrap=aclrtMemcpy -lm'
        report['build_command']=command
        report['compile']=r.run('cvm',prefix+shlex.quote(command),timeout=90)
        report['library_identity']=r.run('cvm',prefix+shlex.quote('sha256sum /data/ascendc/build/libbdszblind.so; g++ --version | head -1'))
        if report['compile']['exit_code']==0:
            check=r.run('cvm',"curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8020/metrics")
            idle=json.loads(check['stdout'])
            if idle.get('active') or idle.get('queued'):raise RuntimeError('Backend became busy; execution skipped')
            command='cd '+shlex.quote(directory)+' && LD_LIBRARY_PATH='+cann+'/lib64:/data/ascendc/build:/usr/local/Ascend/driver/lib64/driver:/usr/local/Ascend/driver/lib64/common OMP_NUM_THREADS=1 timeout 30 ./probe --run-synthetic'
            report['execution']=r.run('cvm',prefix+shlex.quote(command),timeout=45)
        after=r.run('cvm',"curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8020/metrics")
        report['after']=json.loads(after['stdout'])
        report['backend_request_count_unchanged']=report['after'].get('requests')==report['before'].get('requests')
        report['backend_idle_after']=report['after'].get('active')==0 and report['after'].get('queued')==0
    except Exception as exc:report['error_type']=type(exc).__name__
    finally:
        if r:r.close()
        report['finished_ns']=time.time_ns()
        with (a.output_dir/'result.json').open('x',encoding='utf-8') as f:json.dump(report,f,ensure_ascii=False,indent=2)
        print(json.dumps({'directory':str(a.output_dir),'error_type':report.get('error_type'),'compile_exit':report.get('compile',{}).get('exit_code'),'test_exit':report.get('execution',{}).get('exit_code')}))

if __name__=='__main__':main()
