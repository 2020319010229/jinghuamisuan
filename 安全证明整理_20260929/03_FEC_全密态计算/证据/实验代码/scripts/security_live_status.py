"""Read-only deployed hashes, health, replay metadata, and actual running engine."""
import argparse
import json
from pathlib import Path
import shlex
from security_remote import Remote

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();r=Remote();out={}
    commands={
        'backend_health':"curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8020/healthz",
        'gateway_health':"curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8000/healthz",
        'cvm_health':"curl --noproxy '*' -fsS --max-time 5 -X POST -H 'Content-Type: application/json' -d '{}' http://127.0.0.1:8101/internal/health",
        'metrics':"curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8020/metrics",
        'server_hashes':'docker exec cvm-server sha256sum /opt/cvm/cvm_server/generation.py /opt/cvm/cvm_server/replay.py /opt/cvm/cvm_server/request_auth.py /opt/cvm/cvm_server/authenticated_replay.py',
        'engine_process':'docker exec otp-c35-cb python3 -c '+shlex.quote("import pathlib,hashlib,json; out=[]\nfor p in pathlib.Path('/proc').iterdir():\n if p.name.isdigit():\n  try:\n   if (p/'comm').read_text().strip()=='serve35_cb': out.append({'pid':p.name,'exe':str((p/'exe').resolve()),'sha256':hashlib.sha256((p/'exe').read_bytes()).hexdigest()})\n  except (FileNotFoundError,PermissionError):pass\nprint(json.dumps(out))"),
        'replay_metadata':'docker exec cvm-server python3 -c '+shlex.quote("from pathlib import Path; import json,sqlite3; p=Path('/opt/cvm/data/security_replay/replay-v2.sqlite3'); out={'exists':p.exists(),'parent_mode':oct(p.parent.stat().st_mode & 511)}\nif p.exists():\n out['mode']=oct(p.stat().st_mode & 511); c=sqlite3.connect('file:'+str(p)+'?mode=ro',uri=True); out['rows']=c.execute('SELECT COUNT(*) FROM seen').fetchone()[0];c.close()\nprint(json.dumps(out))"),
    }
    try:
        for key,cmd in commands.items():out[key]=r.run('cvm',cmd)
        out['sdk_hashes']=r.run('host','sha256sum /root/client/client.py /root/client/utils/kunpeng_attestation.py /root/client/utils/request_auth.py')
        for name in ('cvm-server','otp-c35-cb'):
            doc=json.loads(r.run('cvm','docker inspect '+name)['stdout'])[0]
            out[name]={'running':doc['State']['Running'],'status':doc['State']['Status'],'started_at':doc['State']['StartedAt'],'restart_count':doc['RestartCount']}
    finally:r.close()
    with a.output.open('x',encoding='utf-8') as f:json.dump(out,f,indent=2)
    print(json.dumps(out,indent=2))

if __name__=='__main__':main()
