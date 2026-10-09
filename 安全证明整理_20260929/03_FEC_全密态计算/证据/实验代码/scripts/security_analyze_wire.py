"""Offline verification of the bounded Ethernet/IPv4/TCP experiment captures."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from security_wire_probe import tcp_frame


def read_capture(path):
    data = path.read_bytes()
    if len(data) < 24 or data[:4] != b'\xd4\xc3\xb2\xa1':
        raise ValueError('Unsupported PCAP header')
    streams = {}
    packets = 0
    pos = 24
    while pos < len(data):
        if len(data) - pos < 16:
            raise ValueError('Truncated packet header')
        _, _, size, original = struct.unpack('<IIII', data[pos:pos+16])
        pos += 16
        if size != original or pos+size > len(data):
            raise ValueError('Truncated frame')
        row = tcp_frame(data[pos:pos+size])
        pos += size
        packets += 1
        if row and row[5]:
            streams.setdefault(row[:4], []).append((row[4], row[5]))
    result = {}
    for flow, chunks in streams.items():
        chunks.sort()
        base = chunks[0][0]
        end = max(seq+len(payload) for seq,payload in chunks)
        if end-base > 10_000_000:
            raise ValueError('Sequence wrap/oversized stream unsupported')
        joined = bytearray(end-base)
        occupied = bytearray(end-base)
        conflicts = 0
        for seq,payload in chunks:
            for i,value in enumerate(payload, seq-base):
                if occupied[i] and joined[i] != value:
                    conflicts += 1
                joined[i] = value
                occupied[i] = 1
        result[flow] = {'bytes':bytes(joined), 'gaps':occupied.count(0), 'overlap_conflicts':conflicts}
    return packets,result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('directory',type=Path)
    parser.add_argument('--sdk',action='store_true')
    args = parser.parse_args()
    doc = json.loads((args.directory/('sdk_result.json' if args.sdk else 'client_result.json')).read_text(encoding='utf-8'))
    if args.sdk:
        doc['synthetic_prompt_marker']='OTPSEC_SDK_'+doc['run_id']
    report = {'scope':'passive visibility of these exact gateway TCP flows only; no active attacker or bus claims',
              'run_id':doc['run_id'], 'captures':{}, 'tests':[]}
    captures = {}
    for name in ('host','cvm'):
        packets, streams = read_capture(args.directory/(name+'.pcap'))
        captures[name] = streams
        rows = []
        for flow,entry in streams.items():
            raw = entry['bytes']
            header, sep, body = raw.partition(b'\r\n\r\n')
            lengths = [int(line.split(b':',1)[1].strip()) for line in header.split(b'\r\n') if line.lower().startswith(b'content-length:')]
            rows.append({'flow':list(flow), 'bytes':len(raw), 'sha256':hashlib.sha256(raw).hexdigest(),
                         'gaps':entry['gaps'],'overlap_conflicts':entry['overlap_conflicts'],
                         'header_complete':bool(sep), 'body_length_matches':len(body)==lengths[0] if lengths else None,
                         'positive_control':doc['wire_control_marker'].encode() in raw,
                         'prompt_marker_visible':doc['synthetic_prompt_marker'].encode() in raw})
        report['captures'][name] = {'packets':packets, 'streams':rows}
    def check(name, passed):
        report['tests'].append({'name':name,'passed':bool(passed)})
    for name,streams in captures.items():
        rows = report['captures'][name]['streams']
        expected=4 if args.sdk else 12
        check(name+'_expected_directional_streams',len(rows)==expected)
        check(name+'_no_gaps_or_conflicting_retransmissions',all(not x['gaps'] and not x['overlap_conflicts'] for x in rows))
        check(name+'_expected_control_headers',sum(x['positive_control'] for x in rows)==expected//2)
        check(name+'_no_synthetic_prompt_marker',not any(x['prompt_marker_visible'] for x in rows))
        check(name+'_http_boundaries_complete',all(x['header_complete'] and x['body_length_matches'] is not False for x in rows))
        for req in doc.get('http',[]):
            matching = [(flow,e) for flow,e in streams.items() if flow[3]==req['client_port'] and flow[2]==8000]
            check(name+'_'+req['name']+'_response_matches_client',len(matching)==1 and matching[0][1]['bytes'].partition(b'\r\n\r\n')[2] == req['response_body'].encode())
    check('host_and_cvm_reassembled_flows_identical',captures['host'].keys()==captures['cvm'].keys() and all(captures['host'][k]['bytes']==captures['cvm'][k]['bytes'] for k in captures['host']))
    report['passed'] = sum(x['passed'] for x in report['tests'])
    report['total'] = len(report['tests'])
    with (args.directory/'analysis.json').open('x',encoding='utf-8') as f:
        json.dump(report,f,ensure_ascii=False,indent=2)
    print(json.dumps({'passed':report['passed'],'total':report['total']}))
    return 0 if report['passed']==report['total'] else 1

if __name__=='__main__':
    raise SystemExit(main())
