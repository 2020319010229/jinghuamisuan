"""Build frozen baseline and RNG-only candidate in fresh /tmp; never deploy."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import tarfile
import time
from security_remote import Remote, PROJECT

EXPECTED='3c50219c2dba722d25f4421d3cfd61d04661848a42143afe41dfe4cb6f807b8d'
FIX='618b8e5543ae4742d3a1e5ce9a39ae199885ada5f0e366970c8eca8dcbc39555'

def main():
    p=argparse.ArgumentParser(); p.add_argument('--output-dir',type=Path,required=True); a=p.parse_args()
    a.output_dir.mkdir(parents=True,exist_ok=False)
    report={'started_ns':time.time_ns(),'scope':'temporary build and independent synthetic probe only'}; remote=None
    try:
        frozen=PROJECT/'delivery/OTP35B_CB_V11_20260903'
        files=sorted(list(frozen.glob('*.c'))+list(frozen.glob('*.h'))+[frozen/'Makefile'])
        report['frozen_source_sha256']={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in files}
        report['fixed_header_sha256']=hashlib.sha256((PROJECT/'otp_rng.h').read_bytes()).hexdigest()
        if report['fixed_header_sha256']!=FIX: raise RuntimeError('Unexpected fixed header identity')
        archive=a.output_dir/'build_inputs.tar'
        with tarfile.open(archive,'w') as t:
            for f in files:t.add(f,arcname='baseline/'+f.name)
            for f in files:t.add(PROJECT/'otp_rng.h' if f.name=='otp_rng.h' else f,arcname='candidate/'+f.name)
            t.add(PROJECT/'scripts/security_npu_probe.cpp',arcname='candidate/security_npu_probe.cpp')
        remote=Remote()
        def run(key,command,timeout=40):
            result=remote.run('cvm',command,timeout=timeout); report[key]=result
            if result['exit_code']:raise RuntimeError(key+' failed')
            return result['stdout']
        report['before']=json.loads(run('metrics_before',"curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8020/metrics"))
        stage=run('new_stage','mktemp -d /tmp/otp-security-rng-stage-20260916.XXXXXX').strip()
        directory=run('new_build','docker exec otp-c35-cb mktemp -d /tmp/otp-security-rng-build-20260916.XXXXXX').strip()
        if not stage.startswith('/tmp/otp-security-rng-stage-20260916.') or not directory.startswith('/tmp/otp-security-rng-build-20260916.'):raise RuntimeError('Unexpected temporary path')
        report['stage']=stage; report['container_directory']=directory
        remote.put('cvm',archive,stage+'/build_inputs.tar')
        run('copy','docker cp '+shlex.quote(stage+'/build_inputs.tar')+' '+shlex.quote('otp-c35-cb:'+directory+'/build_inputs.tar'))
        def inside(key,command,timeout=40):return run(key,'docker exec otp-c35-cb sh -c '+shlex.quote(command),timeout)
        inside('extract','tar -xf '+shlex.quote(directory+'/build_inputs.tar')+' -C '+shlex.quote(directory))
        cann='/usr/local/Ascend/cann-9.1.0/aarch64-linux'
        env='LD_LIBRARY_PATH='+cann+'/lib64:/data/ascendc/build:/usr/local/Ascend/driver/lib64/driver:/usr/local/Ascend/driver/lib64/common'
        inside('toolchain','g++ --version; make --version; sha256sum /data/ascendc/build/libbdszblind.so /opt/otp35/bin/serve35_cb')
        online=inside('online_identity','sha256sum /opt/otp35/bin/serve35_cb').split()[0]
        if online!=EXPECTED:raise RuntimeError('Online binary differs from expected frozen baseline')
        report['baseline_build_command']='cd '+shlex.quote(directory+'/baseline')+' && make serve35_cb'
        inside('baseline_build',report['baseline_build_command'],180)
        baseline=inside('baseline_identity','sha256sum '+shlex.quote(directory+'/baseline/serve35_cb')).split()[0]
        report['baseline_reproduces_online']=baseline==EXPECTED
        if baseline!=EXPECTED:raise RuntimeError('Frozen rebuild is not byte-identical; candidate withheld')
        report['candidate_build_command']='cd '+shlex.quote(directory+'/candidate')+' && make serve35_cb'
        inside('candidate_build',report['candidate_build_command'],180)
        report['candidate_path']=directory+'/candidate/serve35_cb'
        report['candidate_sha256']=inside('candidate_identity','sha256sum '+shlex.quote(report['candidate_path'])).split()[0]
        inside('dependencies',env+' ldd '+shlex.quote(report['candidate_path']))
        probe='cd '+shlex.quote(directory+'/candidate')+' && g++ -O3 -march=armv8.6-a+sve+i8mm+bf16 -std=c++17 -Wall -Wno-unused-function -Wno-deprecated-declarations -pthread -fopenmp -I'+cann+'/include -x c++ security_npu_probe.cpp q8_ops.c st35.c -o probe -L'+cann+'/lib64 -lascendcl -lnnopbase -lopapi -L/data/ascendc/build -lbdszblind -Wl,-rpath,/data/ascendc/build -Wl,--wrap=aclrtMemcpy -lm'
        report['probe_build_command']=probe
        inside('probe_build',probe,90)
        idle=json.loads(run('metrics_before_probe',"curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8020/metrics"))
        if idle.get('active') or idle.get('queued'):raise RuntimeError('Backend busy; probe not started')
        inside('probe_execution','cd '+shlex.quote(directory+'/candidate')+' && '+env+' OMP_NUM_THREADS=1 timeout 30 ./probe --run-synthetic',45)
        report['after']=json.loads(run('metrics_after',"curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8020/metrics"))
        report['production_identity_unchanged']=inside('online_identity_after','sha256sum /opt/otp35/bin/serve35_cb').split()[0]==EXPECTED
        report['request_count_unchanged']=report['after'].get('requests')==report['before'].get('requests')
        report['success']=True
    except Exception as exc:
        report['error_type']=type(exc).__name__; report['error']=str(exc)
    finally:
        if remote:remote.close()
        report['finished_ns']=time.time_ns()
        with (a.output_dir/'result.json').open('x',encoding='utf-8') as f:json.dump(report,f,ensure_ascii=False,indent=2)
        print(json.dumps({k:report.get(k) for k in ('success','error','candidate_path','candidate_sha256')}))

if __name__=='__main__':main()
