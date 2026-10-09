"""Read-only deployment inventory. Deliberately never records full environments."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import time
from security_remote import Remote, PROJECT


def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    report={'started_ns':time.time_ns(),'scope':'read-only preflight; selected non-secret configuration only'}
    r=None
    try:
        r=Remote()
        for target,name,command in [
            ('cvm','backend_metrics',"curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8020/metrics"),
            ('host','sdk_hashes','sha256sum /root/client/client.py /root/client/utils/kunpeng_attestation.py /root/client/utils/crypto_utils.py; test ! -e /root/client/utils/request_auth.py'),
            ('cvm','server_hashes','docker exec cvm-server sha256sum /opt/cvm/cvm_server/generation.py /opt/cvm/cvm_server/replay.py /opt/cvm/cvm_server/http_api.py'),
            ('cvm','server_sources',"docker exec cvm-server find /opt/cvm -maxdepth 2 -type f -name '*.py'"),
            ('cvm','disk','df -h /data /tmp; docker exec cvm-server id'),
        ]:report[name]=r.run(target,command)
        for name in ('cvm-server','otp-c35-cb'):
            raw=r.run('cvm','docker inspect '+name)
            if raw['exit_code']:raise RuntimeError('Cannot inspect container')
            item=json.loads(raw['stdout'])[0]
            safe_keys=('CVM_REPLAY_DB','CVM_USER_DATA_DIR','USER_DATA_DIR','PYTHONPATH','CVM_HTTP_HOST','CVM_HTTP_PORT')
            env={x.split('=',1)[0]:x.split('=',1)[1] for x in item['Config'].get('Env',[]) if '=' in x and x.split('=',1)[0] in safe_keys}
            report[name]={'id':item['Id'],'image':item['Image'],'mounts':item['Mounts'],
                          'working_dir':item['Config']['WorkingDir'],'entrypoint':item['Config']['Entrypoint'],
                          'command':item['Config']['Cmd'],'selected_env':env,
                          'network_mode':item['HostConfig']['NetworkMode'],
                          'restart_policy':item['HostConfig']['RestartPolicy'],
                          'state':{k:item['State'].get(k) for k in ('Status','Running','Pid','StartedAt')}}
    except Exception as exc:report['error_type']=type(exc).__name__
    finally:
        if r:r.close()
        report['finished_ns']=time.time_ns();a.output.parent.mkdir(parents=True,exist_ok=True)
        with a.output.open('x',encoding='utf-8') as f:json.dump(report,f,ensure_ascii=False,indent=2)
        print(json.dumps(report,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
