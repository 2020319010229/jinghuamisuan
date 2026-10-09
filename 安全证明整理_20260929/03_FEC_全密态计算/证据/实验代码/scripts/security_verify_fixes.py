"""Non-deploying verification and review artifacts for the 20260916 candidate."""
import argparse
import ast
import datetime
import difflib
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
CANDIDATE=ROOT/'security_fixes/20260916'
EVIDENCE=ROOT/'results/security_plan_20260916'


def main():
    p=argparse.ArgumentParser();p.add_argument('--batch',required=True);a=p.parse_args()
    out=ROOT/'results/security_fix_20260916';out.mkdir(exist_ok=True)
    report={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'candidate local validation; no production deployment','files':[]}
    for path in sorted(CANDIDATE.rglob('*.py')):
        ast.parse(path.read_text(encoding='utf-8'),filename=str(path))
        report['files'].append({'path':str(path.relative_to(ROOT)),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    report['syntax']='passed'
    command=[sys.executable,'-m','unittest','discover','-s','security_fixes/20260916/tests','-v']
    run=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,encoding='utf-8',errors='replace',env={**__import__('os').environ,'PYTHONIOENCODING':'utf-8'})
    report['tests']={'command':command,'exit_code':run.returncode,'stdout':run.stdout,'stderr':run.stderr}
    report['rng_header_sha256']=hashlib.sha256((ROOT/'otp_rng.h').read_bytes()).hexdigest()
    parts=[]
    pairs=[(EVIDENCE/'server_snapshot/replay.py',CANDIDATE/'server/replay.py','server/replay.py'),
           (EVIDENCE/'server_snapshot/generation.py',CANDIDATE/'server/generation.py','server/generation.py'),
           (EVIDENCE/'sdk_snapshot/client.py',CANDIDATE/'sdk/client.py','sdk/client.py'),
           (EVIDENCE/'sdk_snapshot/utils/kunpeng_attestation.py',CANDIDATE/'sdk/utils/kunpeng_attestation.py','sdk/utils/kunpeng_attestation.py'),
           (ROOT/'delivery/OTP35B_CB_V11_20260903/otp_rng.h',ROOT/'otp_rng.h','otp_rng.h'),
           (EVIDENCE/'scripts_snapshot_03/security_rng_boundary_test.c',ROOT/'scripts/security_rng_boundary_test.c','scripts/security_rng_boundary_test.c'),
           (EVIDENCE/'scripts_snapshot_03/security_run_rng_boundary.py',ROOT/'scripts/security_run_rng_boundary.py','scripts/security_run_rng_boundary.py')]
    changed={new for _,new,_ in pairs}
    pairs.extend((None,path,str(path.relative_to(CANDIDATE)).replace('\\','/')) for path in sorted(CANDIDATE.rglob('*.py')) if path not in changed)
    for old,new,name in pairs:
        before=old.read_text(encoding='utf-8').splitlines(keepends=True) if old else []
        after=new.read_text(encoding='utf-8').splitlines(keepends=True)
        parts.extend(difflib.unified_diff(before,after,fromfile='a/'+name if old else '/dev/null',tofile='b/'+name))
    with (out/('candidate_'+a.batch+'.diff')).open('x',encoding='utf-8',newline='\n') as f:f.write(''.join(parts))
    with (out/('checks_'+a.batch+'.json')).open('x',encoding='utf-8') as f:json.dump(report,f,ensure_ascii=False,indent=2)
    print(json.dumps({'syntax':report['syntax'],'test_exit':run.returncode,'files':len(report['files'])}))
    return run.returncode

if __name__=='__main__':sys.exit(main())
