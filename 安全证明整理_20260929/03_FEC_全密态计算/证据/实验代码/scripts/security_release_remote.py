"""Scoped release helper. Uploaded into a private staging directory; no secret output."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.request

RELEASE='security-20260917-01'
SERVER=Path('/opt/cvm/cvm_server')
SERVER_FILES=['generation.py','replay.py','authenticated_replay.py','request_auth.py']
SDK_FILES=['client.py','utils/kunpeng_attestation.py','utils/request_auth.py']
SERVER_BASE={'generation.py':'84d340d1eea8b2fedf40c38e0c9a2a9d4224b7b67ba3d5fe6d400fa6d04b3b24','replay.py':'fd9f2f87ae73588226b34b8c6a0363e81862df5def60f2d540c524464a4ae626'}
SDK_BASE={'client.py':'8776be0b871c3df44b74d7297a3ec445c480b1db0839a795232318ce3de760b2','utils/kunpeng_attestation.py':'d75e9d4844c9a9af499e25e8d4b840175faf920ef26763f7ebd1f3bf19c7df89'}

def run(*args):
    p=subprocess.run(args,capture_output=True,text=True,timeout=180)
    if p.returncode: raise RuntimeError('Command failed: '+args[0]+' (output withheld)')
    return p.stdout.strip()

def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def atomic_copy(source,target):
    target=Path(target); tmp=target.with_name(target.name+'.'+RELEASE+'.next')
    if tmp.exists():raise RuntimeError('Temporary target already exists')
    shutil.copy2(source,tmp)
    if target.exists():shutil.copymode(target,tmp)
    with tmp.open('rb') as f:os.fsync(f.fileno())
    os.replace(tmp,target)
    fd=os.open(str(target.parent),os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)

def idle():
    with urllib.request.urlopen('http://127.0.0.1:8020/metrics',timeout=5) as f:m=json.load(f)
    if m.get('active')!=0 or m.get('queued')!=0:raise RuntimeError('Backend not idle')
    return m

def inside_hash(container,path):
    return run('docker','exec',container,'sha256sum',str(path)).split()[0]

def stage_cvm(stage,ip):
    idle()
    cfg=json.loads(run('docker','inspect','cvm-server'))[0]
    for name,want in SERVER_BASE.items():
        if inside_hash('cvm-server',SERVER/name)!=want:raise RuntimeError('Server baseline drift')
    for name in SERVER_FILES[2:]:
        if run('docker','exec','cvm-server','python3','-c','from pathlib import Path; print(Path('+repr(str(SERVER/name))+').exists())')!='False':raise RuntimeError('Unexpected existing new module')
    backup='/opt/cvm/data/'+RELEASE+'/server-backup'
    run('docker','exec','cvm-server','mkdir','-m','700','-p',backup)
    # Backup contains environment file and remains on the protected persistent volume.
    run('docker','exec','cvm-server','cp','-a',str(SERVER),backup+'/original')
    oldtag='cvm-server:'+RELEASE+'-before'
    before=run('docker','commit','--pause=false','cvm-server',oldtag)
    ledger=Path(cfg['Mounts'][0]['Source'])/(RELEASE+'-stage-replay')
    ledger.mkdir(mode=0o700)
    name='cvm-server-'+RELEASE+'-stage'
    command=['docker','create','--name',name,'--network',cfg['HostConfig']['NetworkMode'],'-p',ip+':18101:8101','-w',cfg['Config']['WorkingDir']]
    for value in cfg['Config'].get('Env',[]):
        if not value.startswith('CVM_REPLAY_DB='):command+=['-e',value]
    command+=['-e','CVM_REPLAY_DB=/opt/cvm/data/'+RELEASE+'-stage-replay/replay.sqlite3']
    for mount in cfg['Mounts']:
        if mount['Type']!='bind':raise RuntimeError('Unexpected mount type')
        command+=['-v',mount['Source']+':'+mount['Destination']+('' if mount['RW'] else ':ro')]
    for device in cfg['HostConfig'].get('Devices') or []:
        command+=['--device',device['PathOnHost']+':'+device['PathInContainer']+':'+device['CgroupPermissions']]
    command+=[oldtag]+cfg['Config']['Cmd']
    run(*command)
    for file in SERVER_FILES:run('docker','cp',str(stage/'server'/file),name+':'+str(SERVER/file))
    run('docker','start',name)
    return {'stage_container':name,'backup_image':before,'backup_tag':oldtag,'server_backup':backup,'base_url':'http://'+ip+':18101'}

def stage_sdk(stage):
    src=Path('/root/client');dest=stage/'client';dest.mkdir(mode=0o700)
    for name,want in SDK_BASE.items():
        if digest(src/name)!=want:raise RuntimeError('SDK baseline drift')
    if (src/'utils/request_auth.py').exists():raise RuntimeError('Unexpected SDK authentication module')
    for path in src.rglob('*'):
        if path.is_file() and (path.suffix=='.py' or path.name=='.env'):
            target=dest/path.relative_to(src);target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(path,target)
    for name in SDK_FILES:shutil.copy2(stage/'sdk'/name,dest/name)
    return {'client_dir':str(dest)}

def apply_cvm(stage):
    idle()
    for name,want in SERVER_BASE.items():
        if inside_hash('cvm-server',SERVER/name)!=want:raise RuntimeError('Server baseline drift')
    # Run the actual atomic file operations in the existing container.
    target='/tmp/otp-security-release-'+RELEASE
    run('docker','cp',str(stage),'cvm-server:'+target)
    result=run('docker','exec','cvm-server','python3',target+'/security_release_remote.py','server-files','--stage',target)
    run('docker','restart','--time','20','cvm-server')
    return json.loads(result)

def server_files(stage):
    backup=Path('/opt/cvm/data')/RELEASE/'server-backup/original'
    if not (backup/'generation.py').is_file():raise RuntimeError('Missing server backup')
    ledger=Path('/opt/cvm/data/security_replay');ledger.mkdir(mode=0o700,exist_ok=True)
    if ledger.stat().st_mode & 0o077:raise RuntimeError('Unprotected replay directory')
    for name,want in SERVER_BASE.items():
        if digest(SERVER/name)!=want:raise RuntimeError('Server baseline drift')
    env=SERVER/'env/cvm_server.env';data=env.read_text()
    if any(line.strip().startswith('CVM_REPLAY_DB=') for line in data.splitlines()):raise RuntimeError('Replay setting already exists')
    for name in SERVER_FILES:
        ast.parse((stage/'server'/name).read_text())
        if (SERVER/name).is_symlink():raise RuntimeError('Unexpected server symlink')
    for name,want in SERVER_BASE.items():
        if digest(backup/name)!=want:raise RuntimeError('Server backup mismatch')
    if digest(backup/'env/cvm_server.env')!=digest(env):raise RuntimeError('Server environment drift')
    temp=stage/'new-server.env';temp.write_text(data.rstrip()+'\nCVM_REPLAY_DB=/opt/cvm/data/security_replay/replay-v2.sqlite3\n');temp.chmod(0o600)
    try:
        for name in SERVER_FILES:atomic_copy(stage/'server'/name,SERVER/name)
        atomic_copy(temp,env)
    except Exception:
        for name in SERVER_FILES:
            if (backup/name).exists():atomic_copy(backup/name,SERVER/name)
            elif (SERVER/name).is_file():(SERVER/name).unlink()
        atomic_copy(backup/'env/cvm_server.env',env)
        raise
    return {'server_hashes':{n:digest(SERVER/n) for n in SERVER_FILES},'replay_db':'/opt/cvm/data/security_replay/replay-v2.sqlite3'}

def apply_sdk(stage):
    src=Path('/root/client');backup=Path('/root')/RELEASE/'sdk-backup'
    backup.mkdir(parents=True,mode=0o700);backup.parent.chmod(0o700)
    for name,want in SDK_BASE.items():
        if digest(src/name)!=want:raise RuntimeError('SDK baseline drift')
    for name in SDK_FILES:
        ast.parse((stage/'sdk'/name).read_text())
        if (src/name).is_symlink():raise RuntimeError('Unexpected SDK symlink')
    for name in SDK_FILES:
        path=src/name
        if path.exists():
            target=backup/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,target)
    try:
        for name in SDK_FILES:atomic_copy(stage/'sdk'/name,src/name)
    except Exception:
        for name in SDK_FILES:
            if (backup/name).exists():atomic_copy(backup/name,src/name)
            elif (src/name).is_file():(src/name).unlink()
        raise
    return {'backup':str(backup),'sdk_hashes':{n:digest(src/n) for n in SDK_FILES}}

def apply_engine(stage):
    idle()
    current='/opt/otp35/bin/serve35_cb'
    candidate='/tmp/otp-security-rng-build-20260916.7r9qJi/candidate/serve35_cb'
    before='3c50219c2dba722d25f4421d3cfd61d04661848a42143afe41dfe4cb6f807b8d'
    after='3cdae626266c4955003eb3f33f2ce4a466c819604472b5e56c4a0806bdd40e98'
    if inside_hash('otp-c35-cb',current)!=before or inside_hash('otp-c35-cb',candidate)!=after:raise RuntimeError('Engine digest mismatch')
    backup='/data/'+RELEASE+'/engine-backup'
    run('docker','exec','otp-c35-cb','mkdir','-m','700','-p',backup)
    run('docker','exec','otp-c35-cb','cp','-a',current,backup+'/serve35_cb')
    oldimage=run('docker','commit','--pause=false','otp-c35-cb','vllm-otp:'+RELEASE+'-before')
    # Preserve the old running inode. Never truncate an executing binary.
    run('docker','exec','otp-c35-cb','python3','-c','import os,shutil; a='+repr(current)+'; b=a+".'+RELEASE+'.next"; assert not os.path.exists(b); shutil.copy2('+repr(candidate)+',b); shutil.copymode(a,b); f=open(b,"rb"); os.fsync(f.fileno()); f.close(); os.replace(b,a)')
    run('docker','restart','--time','30','otp-c35-cb')
    actual=inside_hash('otp-c35-cb',current)
    if actual!=after:raise RuntimeError('Post-restart engine digest mismatch')
    return {'binary_sha256':actual,'backup':backup,'previous_image':oldimage,'health_verification':'required after model load'}

def sync_source(stage):
    root=Path('/root/docker_l1/jhms-nano-deploy/cvm_server')
    env=root/'env/cvm_server.example.env'
    rng=Path('/data/otp_c35/otp_rng.h')
    if digest(rng)!='9b20a7eefa1d8c7f2329ae7ce1f515305b900ebff845f3d5ab5a7b2b7be96356':raise RuntimeError('Engine source baseline drift')
    if digest(stage/'otp_rng.h')!='618b8e5543ae4742d3a1e5ce9a39ae199885ada5f0e366970c8eca8dcbc39555':raise RuntimeError('Candidate RNG mismatch')
    for name,want in SERVER_BASE.items():
        if digest(root/name)!=want:raise RuntimeError('Build source baseline drift')
    for name in SERVER_FILES[2:]:
        if (root/name).exists():raise RuntimeError('Build source new module already exists')
    if digest(env)!='df5cf38e99fd7e5a2a784ee143fda931e8117027a24b30ef41cf0ba6a3d5b5f8':raise RuntimeError('Build template baseline drift')
    data=env.read_text()
    if any(line.strip().startswith('CVM_REPLAY_DB=') for line in data.splitlines()):raise RuntimeError('Build template setting already exists')
    backup=Path('/data')/RELEASE/'cvm-build-source-backup';backup.mkdir(mode=0o700,parents=True)
    shutil.copy2(rng,backup/'otp_rng.h')
    names=SERVER_FILES+['env/cvm_server.example.env']
    for name in names:
        path=root/name
        if path.is_symlink():raise RuntimeError('Unexpected build source symlink')
        if path.exists():
            target=backup/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,target)
    temp=stage/'new-build-example.env';temp.write_text(data.rstrip()+'\nCVM_REPLAY_DB=/opt/cvm/data/security_replay/replay-v2.sqlite3\n')
    try:
        for name in SERVER_FILES:atomic_copy(stage/'server'/name,root/name)
        atomic_copy(temp,env)
        atomic_copy(stage/'otp_rng.h',rng)
    except Exception:
        for name in names:
            if (backup/name).exists():atomic_copy(backup/name,root/name)
            elif (root/name).is_file():(root/name).unlink()
        atomic_copy(backup/'otp_rng.h',rng)
        raise
    return {'source_root':str(root),'backup':str(backup),'hashes':{name:digest(root/name) for name in names},'engine_source':{'path':str(rng),'sha256':digest(rng)},'note':'Existing persistent security_replay directory is retained; no image rebuild performed'}

def images(stage):
    idle();result={}
    for name in SERVER_FILES:
        if inside_hash('cvm-server',SERVER/name)!=digest(stage/'server'/name):raise RuntimeError('Release server digest mismatch')
    if inside_hash('otp-c35-cb','/opt/otp35/bin/serve35_cb')!='3cdae626266c4955003eb3f33f2ce4a466c819604472b5e56c4a0806bdd40e98':raise RuntimeError('Release engine digest mismatch')
    for port,path in [(8000,'/healthz'),(8020,'/healthz')]:
        with urllib.request.urlopen('http://127.0.0.1:'+str(port)+path,timeout=5) as response:
            if response.status!=200:raise RuntimeError('Release service unhealthy')
    for name,version,alias in [('cvm-server','cvm-server:'+RELEASE,'cvm-server:22.04-arm64'),('otp-c35-cb','vllm-otp:'+RELEASE,'vllm-otp:v11-cb')]:
        image=run('docker','commit','--pause=false',name,version)
        result[name]={'image':image,'versioned_tag':version,'deployment_tag':alias}
    for row in result.values():run('docker','tag',row['image'],row['deployment_tag'])
    run('docker','stop','--time','10','cvm-server-'+RELEASE+'-stage')
    return result

def main():
    p=argparse.ArgumentParser();p.add_argument('action');p.add_argument('--stage',type=Path,default=Path(__file__).parent);p.add_argument('--ip');a=p.parse_args()
    actions={'stage-cvm':lambda:stage_cvm(a.stage,a.ip),'stage-sdk':lambda:stage_sdk(a.stage),'apply-cvm':lambda:apply_cvm(a.stage),'server-files':lambda:server_files(a.stage),'apply-sdk':lambda:apply_sdk(a.stage),'apply-engine':lambda:apply_engine(a.stage),'images':lambda:images(a.stage),'sync-source':lambda:sync_source(a.stage)}
    try:print(json.dumps(actions[a.action](),sort_keys=True))
    except Exception as exc:
        print(json.dumps({'error_type':type(exc).__name__,'message':str(exc) if isinstance(exc,RuntimeError) else 'details withheld'}));sys.exit(1)

if __name__=='__main__':main()
