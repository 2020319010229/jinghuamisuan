"""Read back release tags; verify acceptance semantics and preserve a new evidence batch."""
import ast
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import shutil
from urllib.parse import unquote
from security_remote import Remote,PROJECT

ROOT=PROJECT/'results/security_deploy_20260917'
def read(name):return json.loads((ROOT/name).read_text(encoding='utf-8'))
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    checks=[]
    def check(name,passed):
        checks.append({'name':name,'passed':bool(passed)})
        if not passed:raise RuntimeError('Acceptance failed: '+name)
    fresh=read('live_restart_replay/fresh_request/sdk_result.json')
    check('live_stream',fresh.get('generation',{}).get('passed') and fresh['initialization']['status']==0 and not fresh.get('error_type'))
    check('live_authentication_controls',fresh.get('request_auth_version')==2 and len(fresh['replay_controls'])==5 and all(x['passed'] and x['backend_request_delta']==0 for x in fresh['replay_controls']))
    check('live_ra_enabled',fresh['policy']['remote_attestation_enabled'])
    check('restart_replay',read('live_restart_replay/orchestration.json')['passed'] and read('live_restart_replay/restart_result.json')['passed'])
    nonstream=read('nonstream_live_01/nonstream_result.json');check('nonstream_15',nonstream['passed'] and len(nonstream['tests'])==15 and all(x['passed'] for x in nonstream['tests']))
    pair=read('pair_live_01/pair_result.json');check('pair_11',len(pair['tests'])==11 and all(x['passed'] for x in pair['tests']) and pair['backend_request_delta']==4 and not pair.get('error_type'))
    proof=read('attestation_live_01/controls.json');check('attestation_offline_7',proof['passed']==proof['total']==7)
    live=read('live_status_final.json')
    for key in ['backend_health','gateway_health','cvm_health']:
        value=json.loads(live[key]['stdout']);check(key,live[key]['exit_code']==0 and (value.get('status')=='ok' or value.get('code')==0))
    metrics=json.loads(live['metrics']['stdout']);check('backend_idle',metrics['active']==metrics['queued']==0)
    process=json.loads(live['engine_process']['stdout']);check('running_engine_hash',len(process)==1 and process[0]['sha256']=='3cdae626266c4955003eb3f33f2ce4a466c819604472b5e56c4a0806bdd40e98')
    ledger=json.loads(live['replay_metadata']['stdout']);check('persistent_ledger_permissions',ledger['exists'] and ledger['parent_mode']=='0o700' and ledger['mode']=='0o600')
    for name in ('cvm-server','otp-c35-cb'):check(name+'_running',live[name]['running'] and live[name]['restart_count']==0)
    for key,sub in [('server_hashes','server'),('sdk_hashes','sdk')]:
        for line in live[key]['stdout'].splitlines():
            hash_value,path=line.split(None,1)
            marker='/cvm_server/' if sub=='server' else '/client/'
            local=PROJECT/'security_fixes/20260916'/sub/path.split(marker,1)[1]
            check('deployed_'+sub+'_'+local.name,sha(local)==hash_value)
    source=read('sync_source.json');check('build_source_sync',source['sync-source']['exit_code']==0 and not source.get('error_type'))
    images=json.loads(read('images.json')['images']['stdout']);r=Remote();tags={}
    try:
        for name,row in images.items():
            for tag in (row['versioned_tag'],row['deployment_tag']):
                res=r.run('cvm','docker image inspect --format {{.Id}} '+tag)
                tags[tag]=res['stdout'].strip();check('image_tag_'+tag,res['exit_code']==0 and tags[tag]==row['image'])
        for tag in ('cvm-server:security-20260917-01-before','vllm-otp:security-20260917-01-before'):
            res=r.run('cvm','docker image inspect --format {{.Id}} '+tag)
            tags[tag]=res['stdout'].strip();check('backup_tag_'+tag,res['exit_code']==0 and tags[tag].startswith('sha256:'))
    finally:r.close()
    frozen=PROJECT/'results/security_fix_20260916'
    manifest=json.loads((frozen/'manifest_fix_01.json').read_text(encoding='utf-8'))
    check('previous_frozen_manifest_unchanged',all(sha(frozen/x['path'])==x['sha256'] for x in manifest['files']))
    scripts=['security_release.py','security_release_remote.py','security_live_status.py','security_restart_replay_probe.py','security_run_restart_replay.py','security_sdk_nonstream_probe.py','security_run_sdk_nonstream.py','security_finalize_deployment.py','security_sdk_probe.py','security_run_sdk_probe.py','security_sdk_pair_probe.py','security_run_sdk_pair.py']
    snapshot=ROOT/'snapshot';snapshot.mkdir()
    for name in scripts:
        path=PROJECT/'scripts'/name;ast.parse(path.read_text(encoding='utf-8'));shutil.copy2(path,snapshot/name)
    for name in ('SECURITY_EXECUTION_TRACKER.md','SECURITY_TRUST_BOUNDARIES.md'):shutil.copy2(PROJECT/'docs'/name,snapshot/name)
    check('delivery_script_syntax',True)
    class Links(HTMLParser):
        def __init__(self):super().__init__();self.links=[]
        def handle_starttag(self,tag,attrs):
            if tag=='a':self.links.extend(v for k,v in attrs if k=='href')
    parser=Links();parser.feed((ROOT/'deployment_report.htm').read_text(encoding='utf-8'))
    expected={'acceptance.json','manifest.json'}
    missing=[x for x in parser.links if x not in expected and not (ROOT/unquote(x)).exists()]
    check('report_local_links',not missing)
    out={'scope':'selected repair rollout completed; not full three-scheme security acceptance','passed':True,'checks':checks,'image_tags':tags,'report_links':len(parser.links),'old_frozen_files_verified':len(manifest['files']),'pending':['trusted root and approved measurement references','platform-CVM key binding','full lifecycle/tenant/physical bus tests','power-loss and snapshot rollback tests'],'counts':{'local_regression':33,'rng_boundary':73,'live_attack_controls':5,'restart_replay':1,'nonstream_controls':15,'pair_controls':11,'attestation_offline_controls':7}}
    with (ROOT/'acceptance.json').open('x',encoding='utf-8') as f:json.dump(out,f,ensure_ascii=False,indent=2)
    files=[{'path':p.relative_to(ROOT).as_posix(),'sha256':sha(p)} for p in sorted(ROOT.rglob('*')) if p.is_file() and p.name!='manifest.json']
    with (ROOT/'manifest.json').open('x',encoding='utf-8') as f:json.dump({'scope':'local integrity hashes, not signed provenance','files':files},f,indent=2)
    print(json.dumps({'passed':True,'checks':len(checks),'report_links':len(parser.links),'manifest_files':len(files),'previous_frozen_files':len(manifest['files'])}))

if __name__=='__main__':main()
