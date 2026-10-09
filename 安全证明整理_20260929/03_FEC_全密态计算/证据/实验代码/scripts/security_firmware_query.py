"""Read-only topology/firmware queries; no serial numbers or configuration changes."""
import argparse
import hashlib
import json
from pathlib import Path
import time
from security_remote import Remote

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--board-id',type=int,action='append');a=p.parse_args()
    out={'started_ns':time.time_ns(),'scope':'read-only device mapping plus board firmware version; no setting/reset/upgrade command'};r=None
    try:
        r=Remote()
        out['mapping']=r.run('cvm','npu-smi info -m',timeout=15)
        out['summary']=r.run('cvm','npu-smi info',timeout=15)
        if a.board_id:
            mapped={int(line.split()[0]) for line in out['mapping']['stdout'].splitlines() if line.split() and line.split()[0].isdigit()}
            if not set(a.board_id)<=mapped:raise RuntimeError('Unobserved board ID')
            out['boards']=[]
            for board in a.board_id:
                result=r.run('cvm','npu-smi info -t board -i '+str(board)+' -c 0',timeout=15)
                selected=[line for line in result['stdout'].splitlines() if any(word in line.lower() for word in ('version','firmware','not support','failed','invalid','error'))]
                out['boards'].append({'board_id':board,'exit_code':result['exit_code'],'version_or_error_lines':selected,'raw_stdout_sha256':hashlib.sha256(result['stdout'].encode()).hexdigest(),'omitted_unrelated_lines':True})
    except Exception as exc:out['error_type']=type(exc).__name__
    finally:
        if r:r.close()
        out['finished_ns']=time.time_ns()
        with a.output.open('x',encoding='utf-8') as f:json.dump(out,f,ensure_ascii=False,indent=2)
        print(json.dumps(out,ensure_ascii=False,indent=2))

if __name__=='__main__':main()
