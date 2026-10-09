"""Remove only old experiment DEKs proven by time window AND synthetic ciphertext.
No key bytes or plaintext secrets are printed. Does not enumerate keyring contents.
"""
import argparse
import hashlib
import json
import logging
from pathlib import Path
import re
import sys

def main():
    p=argparse.ArgumentParser(); p.add_argument('--input',type=Path,action='append',required=True); p.add_argument('--output',type=Path,required=True); a=p.parse_args()
    sys.path.insert(0,'/root/client')
    from utils.crypto_utils import CryptoUtils
    logging.disable(logging.CRITICAL)
    directory=Path(CryptoUtils._dek_dir()).resolve()
    report={'scope':'only own test DEKs with matching initialization time and authenticated synthetic output','runs':[]}
    for source in a.input:
        doc=json.loads(source.read_text(encoding='utf-8'))
        events=doc['events']; start=next(x['utc_ns'] for x in events if x['name']=='identity_verification_start'); end=next(x['utc_ns'] for x in events if x['name']=='identity_verification_end')
        wire=doc['done']['encryption_generationdata_outputdata']; expected=doc['generation']['synthetic_output']
        row={'run_id':doc['run_id'],'initialization_window_ns':[start,end],'candidates':[],'removed_count':0}
        for path in directory.glob('dek_*.hex') if directory.is_dir() else []:
            if path.is_symlink() or path.resolve().parent!=directory or not re.fullmatch(r'dek_[0-9]+\.hex',path.name): continue
            meta=path.stat()
            if not start<=meta.st_mtime_ns<=end: continue
            key_id=int(path.stem[4:]); item={'test_key_id':key_id,'mtime_ns':meta.st_mtime_ns,'size':meta.st_size,'authenticated_synthetic_match':False}
            try:
                key=CryptoUtils.get_dek(key_id)
                plain=CryptoUtils.decrypt_aes_gcm_from_blob(CryptoUtils.encrypted_blob_wire_decode(wire),key)
                item['authenticated_synthetic_match']=plain==expected
                if plain==expected:
                    CryptoUtils.remove_dek(key_id)
                    try:
                        CryptoUtils.get_dek(key_id); absent=False
                    except ValueError: absent=True
                    item['absent_after_cleanup']=absent
                    if absent: row['removed_count']+=1
                del key
            except Exception as exc: item['error_type']=type(exc).__name__
            row['candidates'].append(item)
        row['resolved']=row['removed_count']==1
        if not row['resolved']: row['note']='No unique confirmed removal; do not delete other keys or enumerate keyring.'
        report['runs'].append(row)
    with a.output.open('x',encoding='utf-8') as f: json.dump(report,f,ensure_ascii=False,indent=2)
    print(json.dumps({'removed_count':sum(x['removed_count'] for x in report['runs']),'all_runs_resolved':all(x['resolved'] for x in report['runs'])}))

if __name__=='__main__': main()
