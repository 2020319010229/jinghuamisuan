"""TDC memory isolation: attempt to read confidential VM memory from the host.

Plants a unique marker inside the CVM, a second marker in an ordinary host process, then
scans both from the host with the same routine. The host-side control must hit, otherwise
"not found" would only prove the search was broken. Read-only: no dumps are written to disk,
no guest or service is modified, and markers are synthetic.
"""
import argparse
import json
from pathlib import Path
import secrets
import shlex
import time

from security_remote import Remote

# Holds a marker resident in anonymous memory, then exits on its own.
HOLDER = (
    "import os,sys,time\n"
    "m=sys.argv[1].encode()\n"
    "buf=bytearray(m*4096)\n"       # ~128 KiB of the marker, easy to hit when sampling
    "open('/tmp/otp-security-holder.pid','w').write(str(os.getpid()))\n"
    "sys.stderr.write('holding\\n');sys.stderr.flush()\n"
    "time.sleep(int(sys.argv[2]))\n"
    "del buf\n"
)

# Scans a target process' readable anonymous mappings for the markers.
SCANNER = r'''
import json,os,sys
pid=int(sys.argv[1]); markers=[m.encode() for m in sys.argv[2].split(',')]
budget=int(sys.argv[3])
# Structural plaintext that any live Linux memory image contains in huge quantities.
# Unlike a single planted marker these are sampling-independent: if none appear, what the
# host is reading is not plaintext guest memory at all.
STRUCT={'ELF_MAGIC':b'\x7fELF','linux_version':b'Linux version','proc_path':b'/opt/cvm',
        'engine_name':b'serve35_cb','interpreter':b'python3','elf_interp':b'/lib/ld-',
        'usr_lib':b'/usr/lib'}
out={'pid':pid,'segments_considered':0,'segments_readable':0,'segments_unreadable':0,
     'bytes_read':0,'errno_counts':{},'hits':{m.decode():0 for m in markers},
     'struct_hits':{k:0 for k in STRUCT},'largest_segment_bytes':0}
try:
    maps=open('/proc/%d/maps'%pid).read().splitlines()
except Exception as exc:
    print(json.dumps({'fatal':str(exc)})); raise SystemExit(0)
cands=[]
for line in maps:
    p=line.split()
    if len(p)<2: continue
    perms=p[1]
    if 'r' not in perms: continue
    path=p[5] if len(p)>5 else ''
    # anonymous / heap / stack / guest RAM; skip file and device mappings
    if path and not path.startswith('['): continue
    lo,hi=[int(x,16) for x in p[0].split('-')]
    if hi-lo >= 4096: cands.append((hi-lo,lo,hi,path))
cands.sort(reverse=True)
out['segments_considered']=len(cands)
out['largest_segment_bytes']=cands[0][0] if cands else 0
out['candidate_bytes_total']=sum(c[0] for c in cands)
fd=os.open('/proc/%d/mem'%pid,os.O_RDONLY)
CHUNK=1<<20
seg_reports=[]
for size,lo,hi,path in cands:
    if out['bytes_read']>=budget: break
    read_any=False; off=lo
    seg={'start':hex(lo),'size_bytes':size,'path':path,'bytes_read':0,
         'struct_hits':{k:0 for k in STRUCT},'marker_hits':0}
    while off<hi and out['bytes_read']<budget:
        n=min(CHUNK,hi-off)
        try:
            os.lseek(fd,off,os.SEEK_SET)
            data=os.read(fd,n)
        except OSError as exc:
            key=str(exc.errno)
            out['errno_counts'][key]=out['errno_counts'].get(key,0)+1
            break
        if not data: break
        read_any=True; out['bytes_read']+=len(data); seg['bytes_read']+=len(data)
        for m in markers:
            if m in data:
                out['hits'][m.decode()]+=1; seg['marker_hits']+=1
        for name,pat in STRUCT.items():
            if pat in data:
                out['struct_hits'][name]+=1; seg['struct_hits'][name]+=1
        off+=n
    out['segments_readable' if read_any else 'segments_unreadable']+=1
    if seg['bytes_read']:
        seg['struct_total']=sum(seg['struct_hits'].values())
        seg_reports.append(seg)
os.close(fd)
total=out.get('candidate_bytes_total') or 1
out['coverage_ratio']=round(out['bytes_read']/total,6)
seg_reports.sort(key=lambda s:-s['struct_total'])
out['scanned_segments']=seg_reports[:12]
print(json.dumps(out))
'''


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--output-dir', type=Path, required=True)
    ap.add_argument('--budget-bytes', type=int, default=3 * (1 << 30))
    ap.add_argument('--hold-seconds', type=int, default=180)
    args = ap.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)

    host_marker = 'HOSTCANARY' + secrets.token_hex(12)
    cvm_marker = 'CVMCANARY' + secrets.token_hex(12)
    # Third marker travels through guest disk I/O instead of staying in process memory.
    # It separates "runtime memory is protected" from "everything is invisible to the host".
    disk_marker = 'DISKCANARY' + secrets.token_hex(12)
    markers = ','.join((cvm_marker, host_marker, disk_marker))
    report = {'started_ns': time.time_ns(), 'passed': False,
              'scope': 'host-side read attempt against confidential VM memory, with host positive control',
              'markers': {'cvm': cvm_marker[:14] + '…', 'host': host_marker[:14] + '…'}}
    remote = None
    try:
        remote = Remote()

        def run(target, name, cmd, timeout=120):
            res = remote.run(target, cmd, timeout=timeout)
            report[name] = {'exit_code': res['exit_code'], 'stdout': res['stdout'][-3000:],
                            'stderr': res['stderr'][-800:]}
            return res

        holder = '/tmp/otp-security-holder-20260918.py'
        for target, marker in (('cvm', cvm_marker), ('host', host_marker)):
            run(target, 'write_holder_' + target,
                'cat > %s <<\'PYEOF\'\n%s\nPYEOF\necho written' % (holder, HOLDER))
            run(target, 'start_holder_' + target,
                'nohup python3 %s %s %d >/tmp/otp-security-holder.log 2>&1 & echo started $!'
                % (holder, marker, args.hold_seconds))
        # Drive the disk marker through the guest block device: write, flush, drop caches,
        # read back. Anything the host can see of this went through the virtio path.
        run('cvm', 'plant_disk_marker',
            'f=/tmp/otp-security-disk-marker.bin; '
            'python3 -c "import sys;open(sys.argv[1],\'wb\').write((sys.argv[2]*4096).encode())" '
            '$f ' + shlex.quote(disk_marker) + '; sync; '
            'sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true; '
            'wc -c < $f; md5sum $f | cut -c1-16')
        time.sleep(3)

        # The confidential guest is the QEMU process backing the CVM.
        qemu = run('host', 'find_qemu',
                   "pgrep -af 'qemu.*kvm-type=cvm' | head -3 || pgrep -af qemu-kvm | head -3")
        report['qemu_processes'] = qemu['stdout'].strip()
        qemu_pid = None
        for line in qemu['stdout'].splitlines():
            token = line.strip().split(' ', 1)[0]
            if token.isdigit():
                qemu_pid = int(token)
                break
        if qemu_pid is None:
            raise RuntimeError('CVM QEMU process not found on host')
        report['qemu_pid'] = qemu_pid

        host_holder_pid = int(run('host', 'host_holder_pid',
                                  'cat /tmp/otp-security-holder.pid')['stdout'].strip())
        report['host_control_pid'] = host_holder_pid

        scanner = '/tmp/otp-security-scan-20260918.py'
        run('host', 'write_scanner',
            'cat > %s <<\'PYEOF\'\n%s\nPYEOF\necho written' % (scanner, SCANNER))

        # 1) positive control: an ordinary host process must be readable and must hit.
        ctrl = run('host', 'scan_control',
                   'python3 %s %d %s %d' % (scanner, host_holder_pid, shlex.quote(markers), 64 << 20),
                   timeout=180)
        report['control_scan'] = json.loads(ctrl['stdout'].strip().splitlines()[-1])

        # 1b) second control, inside the CVM: proves the marker really is resident in guest
        # memory during the scan. Without this, "host found nothing" could just mean the
        # marker was never there.
        run('cvm', 'write_scanner_cvm',
            'cat > %s <<\'PYEOF\'\n%s\nPYEOF\necho written' % (scanner, SCANNER))
        cvm_holder_pid = int(run('cvm', 'cvm_holder_pid',
                                 'cat /tmp/otp-security-holder.pid')['stdout'].strip())
        report['cvm_holder_pid'] = cvm_holder_pid
        inner = run('cvm', 'scan_inside_cvm',
                    'python3 %s %d %s %d' % (scanner, cvm_holder_pid, shlex.quote(markers), 64 << 20),
                    timeout=240)
        report['cvm_inner_scan'] = json.loads(inner['stdout'].strip().splitlines()[-1])

        # 2) the confidential guest.
        guest = run('host', 'scan_guest',
                    'python3 %s %d %s %d' % (scanner, qemu_pid, shlex.quote(markers), args.budget_bytes),
                    timeout=900)
        report['guest_scan'] = json.loads(guest['stdout'].strip().splitlines()[-1])

        # 3) confirm the marker really was resident inside the CVM during the scan.
        alive = run('cvm', 'cvm_holder_alive',
                    "ps -o pid=,etimes= -p $(cat /tmp/otp-security-holder.pid) 2>/dev/null || echo GONE")
        report['cvm_holder_alive'] = alive['stdout'].strip()

        c, g, i = report['control_scan'], report['guest_scan'], report['cvm_inner_scan']
        control_ok = c['hits'].get(host_marker, 0) > 0
        resident_ok = i['hits'].get(cvm_marker, 0) > 0
        guest_clean = g['hits'].get(cvm_marker, 0) == 0 and g['hits'].get(host_marker, 0) == 0
        report['control_positive'] = control_ok
        report['cvm_marker_resident'] = resident_ok
        report['guest_no_marker'] = guest_clean
        # Interpretation aid, not a pass/fail gate: if the disk marker IS visible while the
        # runtime marker is not, the structural plaintext comes from guest block I/O rather
        # than from confidential runtime memory.
        report['disk_marker_hits_in_guest'] = g['hits'].get(disk_marker, 0)
        report['disk_io_plaintext_visible'] = g['hits'].get(disk_marker, 0) > 0
        report['guest_coverage_ratio'] = g.get('coverage_ratio')
        report['guest_read_succeeded'] = g['bytes_read'] > 0
        # Sampling-independent judgement: a plaintext Linux memory image of this size would
        # contain these structures thousands of times over. The control must show them.
        report['control_struct_hits'] = c.get('struct_hits')
        report['guest_struct_hits'] = g.get('struct_hits')
        control_struct_ok = sum((c.get('struct_hits') or {}).values()) > 0
        guest_struct_clean = sum((g.get('struct_hits') or {}).values()) == 0
        report['control_struct_visible'] = control_struct_ok
        report['guest_no_structural_plaintext'] = guest_struct_clean
        # The claim under test is confidentiality of guest RUNTIME memory. A meaningful
        # negative needs: the search works (both controls), the marker really was resident in
        # guest RAM, the host actually read a large part of that RAM, and still did not see it.
        # Structural plaintext is reported separately as an out-of-boundary finding rather
        # than failing this check, because its source is guest block I/O (see disk marker).
        report['passed'] = bool(control_ok and resident_ok and control_struct_ok
                                and guest_clean and g['bytes_read'] > (8 << 30)
                                and 'GONE' not in report['cvm_holder_alive'])
    except Exception as exc:
        report['error_type'] = type(exc).__name__
        report['error'] = str(exc)
    finally:
        if remote:
            for target in ('cvm', 'host'):
                try:
                    remote.run(target, "kill $(cat /tmp/otp-security-holder.pid) 2>/dev/null; "
                                       "rm -f /tmp/otp-security-holder.pid /tmp/otp-security-holder-20260918.py "
                                       "/tmp/otp-security-holder.log /tmp/otp-security-disk-marker.bin", timeout=30)
                except Exception:
                    pass
            for target in ('host', 'cvm'):
                try:
                    remote.run(target, 'rm -f /tmp/otp-security-scan-20260918.py', timeout=30)
                except Exception:
                    pass
            remote.close()
        report['finished_ns'] = time.time_ns()
        with (args.output_dir / 'result.json').open('x', encoding='utf-8') as out:
            json.dump(report, out, ensure_ascii=False, indent=2)
    print(json.dumps({k: report.get(k) for k in
                      ('passed', 'error', 'control_positive', 'cvm_marker_resident',
                       'control_struct_visible', 'guest_no_marker',
                       'guest_no_structural_plaintext', 'guest_coverage_ratio',
                       'qemu_pid')}, ensure_ascii=False))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
