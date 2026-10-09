#!/usr/bin/env python3
"""Orchestrate a bounded synthetic request with two flow-filtered network captures."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import time
from security_remote import Remote, PROJECT, credentials


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--sdk',action='store_true')
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    r = None
    metadata = {'started_ns':time.time_ns(), 'scope':'gateway 8000; client is host, two distinct capture locations only',
                'remote_identity':'existing SSH credentials; host key not independently verified', 'remote_dirs':{}}
    host_in = cvm_in = None
    try:
        r = Remote()
        for target in ('host','cvm'):
            result = r.run(target, 'mktemp -d /tmp/otp-security-wire-20260916.XXXXXX')
            if result['exit_code']:
                raise RuntimeError('Cannot create experiment directory')
            directory = result['stdout'].strip()
            if not directory.startswith('/tmp/otp-security-wire-20260916.') or '\n' in directory:
                raise RuntimeError('Unexpected temporary path')
            metadata['remote_dirs'][target] = directory
            r.put(target, Path(__file__).with_name('security_wire_probe.py'), directory+'/security_wire_probe.py')
        hd, cd = metadata['remote_dirs']['host'], metadata['remote_dirs']['cvm']
        if args.sdk:
            metadata['scope']='SDK 8101; host-client and CVM capture; authentication header must be absent'
            r.put('host',Path(__file__).with_name('security_sdk_probe.py'),hd+'/security_sdk_probe.py')
            command='timeout 150 python3 -u '+shlex.quote(hd+'/security_sdk_probe.py')+' --capture --directory '+shlex.quote(hd)+' --base-url '+shlex.quote('http://'+credentials.CVM+':8101')
        else:
            r.put('host', PROJECT/'tee_crypto.py', hd+'/tee_crypto.py')
            command = 'timeout 150 python3 -u '+shlex.quote(hd+'/security_wire_probe.py')+' client --directory '+shlex.quote(hd)+' --server '+shlex.quote(credentials.CVM)
        host_in, host_out, host_err = r.host.exec_command(command, timeout=160)
        ready = json.loads(host_out.readline())
        metadata['flow_selection'] = ready
        ports = ','.join(map(str,ready['ports']))
        command = 'timeout 150 python3 -u '+shlex.quote(cd+'/security_wire_probe.py')+' capture --directory '+shlex.quote(cd)+' --server '+shlex.quote(credentials.CVM)+' --peer '+shlex.quote(ready['peer'])+' --ports '+shlex.quote(ports)
        if args.sdk:
            command+=' --server-port 8101'
        cvm_in, cvm_out, cvm_err = r.cvm.exec_command(command, timeout=160)
        if not json.loads(cvm_out.readline()).get('ready'):
            raise RuntimeError('CVM capture not ready')
        host_in.write('go\n'); host_in.flush()
        metadata['client_stdout'] = host_out.read().decode('utf-8','replace')
        metadata['client_stderr'] = host_err.read().decode('utf-8','replace')
        metadata['client_exit'] = host_out.channel.recv_exit_status()
        cvm_in.write('stop\n'); cvm_in.flush()
        metadata['cvm_stdout'] = cvm_out.read().decode('utf-8','replace')
        metadata['cvm_stderr'] = cvm_err.read().decode('utf-8','replace')
        metadata['cvm_exit'] = cvm_out.channel.recv_exit_status()
        for target, name in [('host','sdk_result.json' if args.sdk else 'client_result.json'), ('host','host.pcap'), ('cvm','capture_result.json'), ('cvm','cvm.pcap')]:
            r.get(target, metadata['remote_dirs'][target]+'/'+name, args.output_dir/name)
    except Exception as exc:
        metadata['error_type'] = type(exc).__name__
    finally:
        for stream in (host_in,cvm_in):
            if stream:
                stream.close()
        if r:
            r.close()
        metadata['finished_ns'] = time.time_ns()
        metadata['script_hashes'] = {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__),Path(__file__).with_name('security_wire_probe.py'),PROJECT/'tee_crypto.py']}
        if args.sdk:
            metadata['script_hashes']['security_sdk_probe.py']=hashlib.sha256(Path(__file__).with_name('security_sdk_probe.py').read_bytes()).hexdigest()
        with (args.output_dir/'orchestration.json').open('x',encoding='utf-8') as f:
            json.dump(metadata,f,ensure_ascii=False,indent=2)
        print(json.dumps({'output_dir':str(args.output_dir),'error_type':metadata.get('error_type'),'client_exit':metadata.get('client_exit')}))

if __name__ == '__main__':
    main()
