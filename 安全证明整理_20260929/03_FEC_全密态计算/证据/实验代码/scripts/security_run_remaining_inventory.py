"""Fill bounded baseline gaps; no deployment, model copies, or secret environment reads."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import time
from security_remote import Remote

def main():
    p=argparse.ArgumentParser();p.add_argument('--output-dir',type=Path,required=True);a=p.parse_args();a.output_dir.mkdir(parents=True,exist_ok=False)
    out={'started_ns':time.time_ns(),'scope':'read-only remaining baseline metadata and mapped model file hashes'};r=None
    try:
        r=Remote()
        for target in ('host','cvm'):
            out[target+'_firmware']=r.run(target,"for p in /usr/local/Ascend/firmware/version.info /usr/local/Ascend/driver/version.info /etc/ascend_install.info; do if test -f \"$p\"; then printf '%s\\n' \"$p\"; awk -F= '/^[[:space:]]*(Version|version|Firmware_Version|Driver_Version|driver_version|firmware_version)[[:space:]]*=/ {print}' \"$p\"; fi; done")
        out['device_help']=r.run('cvm','npu-smi info -h',timeout=15)
        before=r.run('cvm',"curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8020/metrics")
        out['before']=json.loads(before['stdout'])
        if out['before']['active'] or out['before']['queued']:raise RuntimeError('Backend busy')
        tmp=r.run('cvm','mktemp -d /tmp/otp-security-inventory-20260917.XXXXXX');directory=tmp['stdout'].strip()
        if tmp['exit_code'] or not directory.startswith('/tmp/otp-security-inventory-20260917.'):raise RuntimeError('Temporary directory failed')
        path=Path(__file__).with_name('security_model_inventory.py');out['probe_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
        r.put('cvm',path,directory+'/security_model_inventory.py')
        copy=r.run('cvm','docker cp '+shlex.quote(directory+'/security_model_inventory.py')+' otp-c35-cb:'+shlex.quote(directory+'.py'))
        if copy['exit_code']:raise RuntimeError('Probe copy failed')
        result=r.run('cvm','docker exec otp-c35-cb timeout 300 python3 '+shlex.quote(directory+'.py')+' --hash-weights',timeout=320)
        out['model_execution']=result
        records=[json.loads(x) for x in result['stdout'].splitlines() if x.startswith('{')]
        summaries=[x['result'] for x in records if x.get('event')=='result']
        if summaries:out['model_manifest']=summaries[-1]
        out['model_manifest_complete']=result['exit_code']==0 and bool(summaries)
    except Exception as exc:out['error_type']=type(exc).__name__
    finally:
        if r:
            try:
                result=r.run('cvm',"curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8020/metrics")
                out['after']=json.loads(result['stdout'])
                out['backend_request_count_unchanged']=out['after']['requests']==out.get('before',{}).get('requests')
                out['backend_idle_after']=out['after']['active']==out['after']['queued']==0
            except Exception as exc:out['after_error_type']=type(exc).__name__
            r.close()
        out['finished_ns']=time.time_ns()
        with (a.output_dir/'result.json').open('x',encoding='utf-8') as f:json.dump(out,f,ensure_ascii=False,indent=2)
        print(json.dumps({'output':str(a.output_dir),'error_type':out.get('error_type'),'model_manifest_complete':out.get('model_manifest_complete')}))

if __name__=='__main__':main()
