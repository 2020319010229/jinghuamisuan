"""Read-only selected process metadata. Never dumps full argv, env, or key bytes."""
import hashlib
import json
import os
from pathlib import Path
import stat
import time

def digest(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
    return h.hexdigest()

def main():
    result={'utc_ns':time.time_ns(),'processes':[],'source_hashes':{}}
    value_flags={'--model','--port','--device-id','--slots','--prefill-chunk','--batch-wait-us','--max-ctx','--r-scale','--host','--backend','--backends','--backend-capacity'}
    bool_flags={'--otp-rns','--plain','--plain-tp2','--strict','--tp2'}
    for directory in Path('/proc').iterdir():
        if not directory.name.isdigit(): continue
        try:
            comm=(directory/'comm').read_text().strip()
            argv=(directory/'cmdline').read_bytes().decode('utf-8','replace').split('\0')
            relevant=comm=='serve35_cb' or comm.startswith('qemu-system') or any(x.endswith('/tee_gateway.py') or x=='tee_gateway.py' for x in argv)
            if not relevant: continue
            row={'pid':int(directory.name),'comm':comm,'exe':os.readlink(directory/'exe'),'exe_sha256':digest(directory/'exe')}
            if comm.startswith('qemu-system'):
                row['tmm_guest_object_present']=any(x.startswith('tmm-guest,') for x in argv)
                row['confidential_guest_support_argument_present']=any('confidential-guest-support=' in x for x in argv)
                row['vfio_device_arguments']=[x for x in argv if x.startswith('vfio-pci,') and 'host=' in x]
            else:
                row['cwd']=os.readlink(directory/'cwd')
                for arg in argv:
                    if arg.endswith('tee_gateway.py'):
                        script=arg if arg.startswith('/') else row['cwd']+'/'+arg
                        row['gateway_script_path']=script
                        actual=directory/'root'/script.lstrip('/')
                        if actual.is_file(): row['gateway_script_sha256']=digest(actual)
                row['selected_args']={}
                for i,arg in enumerate(argv):
                    if arg in bool_flags: row['selected_args'][arg]=True
                    elif arg in value_flags and i+1<len(argv): row['selected_args'][arg]=argv[i+1]
                env=(directory/'environ').read_bytes().decode('utf-8','replace').split('\0')
                row['selected_env']={x.split('=',1)[0]:x.split('=',1)[1] for x in env if '=' in x and x.split('=',1)[0] in ('OTP_RNS_NO_VERIFY','OTP_RNS_DEBUG','OMP_NUM_THREADS','ASCEND_RT_VISIBLE_DEVICES')}
                row['mapped_model_files']=sorted({line.split(maxsplit=5)[-1] for line in (directory/'maps').read_text().splitlines() if '/data/Qwen3.5-35B-A3B-w8a8-mtp/' in line})
                row['cgroup']=(directory/'cgroup').read_text().strip()
            result['processes'].append(row)
        except (FileNotFoundError,PermissionError,ProcessLookupError):
            continue
    for name in ('q8_ops.c','q8_ops.h','otp_rng.h','f16_ops.c','moe_ops.c','attn_ops.c','model35.c','serve35_cb.c','tee_gateway.py','tee_crypto.py','serve35_cb'):
        path=Path('/data/otp_c35')/name
        if path.is_file(): result['source_hashes'][str(path)]=digest(path)
    key=Path('/data/otp_c35/.tee_x25519.key')
    if key.exists():
        s=key.stat(); result['transport_key_metadata']={'mode':oct(stat.S_IMODE(s.st_mode)),'uid':s.st_uid,'gid':s.st_gid,'size':s.st_size,'content_read':False}
    print(json.dumps(result,ensure_ascii=False))

if __name__=='__main__': main()
