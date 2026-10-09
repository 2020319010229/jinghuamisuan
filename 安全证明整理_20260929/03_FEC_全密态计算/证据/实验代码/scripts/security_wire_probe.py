#!/usr/bin/env python3
"""Synthetic gateway experiment. AF_PACKET stores only explicitly reserved TCP flows.

This is NOT a PCIe capture, an SDK test, or proof of remote identity. No private
key or shared secret is serialized. All generated plaintext is synthetic.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import struct
import sys
import threading
import time
import uuid


def tcp_frame(frame):
    if len(frame) < 54:
        return None
    kind = struct.unpack('!H', frame[12:14])[0]
    offset = 14
    while kind in (0x8100, 0x88a8):
        if len(frame) < offset + 4:
            return None
        kind = struct.unpack('!H', frame[offset+2:offset+4])[0]
        offset += 4
    if kind != 0x0800 or frame[offset] >> 4 != 4:
        return None
    ihl = (frame[offset] & 15) * 4
    if ihl < 20 or len(frame) < offset + ihl + 20 or frame[offset+9] != 6:
        return None
    # IPv4 fragments would require separate reassembly; explicitly exclude.
    if struct.unpack('!H', frame[offset+6:offset+8])[0] & 0x3fff:
        return None
    total = struct.unpack('!H', frame[offset+2:offset+4])[0]
    src = socket.inet_ntoa(frame[offset+12:offset+16])
    dst = socket.inet_ntoa(frame[offset+16:offset+20])
    tcp = offset + ihl
    sport, dport, seq = struct.unpack('!HHI', frame[tcp:tcp+8])
    start = tcp + (frame[tcp+12] >> 4) * 4
    return (src, dst, sport, dport, seq, frame[start:offset+total])


class Capture:
    def __init__(self, path, peer, server, ports, server_port=8000):
        self.path = Path(path)
        self.peer, self.server = peer, server
        self.ports, self.server_port = set(ports), server_port
        self.stop_event = threading.Event()
        self.count = 0
        self.error = None
        self.file = self.sock = self.thread = None

    def matches(self, row):
        src, dst, sp, dp = row[:4]
        return ((src == self.peer and dst == self.server and sp in self.ports and dp == self.server_port)
                or (dst == self.peer and src == self.server and dp in self.ports and sp == self.server_port))

    def start(self):
        self.file = self.path.open('xb')
        self.file.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4*1024*1024)
        self.sock.settimeout(0.2)
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    def loop(self):
        try:
            while not self.stop_event.is_set():
                try:
                    frame = self.sock.recv(262144)
                except socket.timeout:
                    continue
                row = tcp_frame(frame)
                if row is None or not self.matches(row):
                    continue
                ns = time.time_ns()
                self.file.write(struct.pack('<IIII', ns//10**9, (ns%10**9)//1000, len(frame), len(frame)))
                self.file.write(frame)
                self.count += 1
        except Exception as exc:
            self.error = type(exc).__name__

    def stop(self):
        self.stop_event.set()
        if self.thread: self.thread.join(timeout=2)
        try:
            stats = struct.unpack('II', self.sock.getsockopt(263, 6, 8))
        except (OSError,AttributeError):
            stats = (None, None)
        if self.sock: self.sock.close()
        if self.file: self.file.close()
        return {'packets_saved': self.count, 'capture_error': self.error,
                'socket_received_all_traffic': stats[0], 'socket_drops_all_traffic': stats[1],
                'filter': {'peer': self.peer, 'server': self.server,
                           'client_ports': sorted(self.ports), 'server_port': self.server_port},
                'timestamp_source': 'userspace receive time',
                'pcap_sha256': hashlib.sha256(self.path.read_bytes()).hexdigest() if self.path.exists() else None}


def client(args):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from tee_crypto import b64d, b64e, public_bytes, derive_key, seal_json, open_json, REQUEST_AAD, RESPONSE_AAD
    directory = Path(args.directory)
    route = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    route.connect((args.server, 8000))
    peer = route.getsockname()[0]
    route.close()
    sockets = []
    for _ in range(6):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((peer, 0))
        s.settimeout(90)
        sockets.append(s)
    ports = [s.getsockname()[1] for s in sockets]
    capture = Capture(directory/'host.pcap', peer, args.server, ports)
    capture.start()
    run_id = uuid.uuid4().hex
    report = {'run_id': run_id, 'scope': 'host-client to CVM gateway 8000, not SDK 8101',
              'started_ns': time.time_ns(), 'events': [], 'http': [], 'tests': [],
              'synthetic_prompt_marker': 'OTPSEC_PROMPT_'+run_id,
              'wire_control_marker': 'OTPSEC_HEADER_'+run_id,
              'identity_limit': 'Public key fetched over HTTP, no attestation or trusted key binding.'}
    def event(name):
        report['events'].append({'name': name, 'utc_ns': time.time_ns(), 'monotonic_ns': time.monotonic_ns()})
    def request(index, name, method, path, body=None):
        raw = json.dumps(body, separators=(',', ':')).encode() if body is not None else None
        con = http.client.HTTPConnection(args.server, 8000, timeout=90)
        s = sockets[index]
        event(name+'_connect_start')
        s.connect((args.server, 8000))
        con.sock = s
        event(name+'_submit')
        headers = {'X-Experiment-ID': report['wire_control_marker'], 'Connection': 'close'}
        if raw is not None:
            headers['Content-Type'] = 'application/json'
        con.request(method, path, body=raw, headers=headers)
        response = con.getresponse()
        event(name+'_response_headers')
        first = response.read(1)
        event(name+'_first_body_byte')
        value = first + response.read()
        event(name+'_response_complete')
        report['http'].append({'name': name, 'method': method, 'path': path,
                               'client_port': ports[index], 'status': response.status,
                               'request_body': body, 'response_body': value.decode('utf-8','replace'),
                               'response_sha256': hashlib.sha256(value).hexdigest()})
        con.close()
        return response.status, json.loads(value)
    def check(name, passed):
        report['tests'].append({'name': name, 'passed': bool(passed)})
    print(json.dumps({'ready': True, 'peer': peer, 'ports': ports}), flush=True)
    try:
        if sys.stdin.readline().strip() != 'go':
            raise RuntimeError('No capture readiness confirmation')
        status, health = request(0, 'health', 'GET', '/healthz')
        check('healthy_idle_before', status == 200 and health.get('backend',{}).get('inflight_requests') == 0)
        if not report['tests'][-1]['passed']:
            raise RuntimeError('Service not idle; inference skipped')
        event('identity_fetch_start')
        status, pk = request(1, 'public_key', 'GET', '/v1/tee/public-key')
        if status != 200:
            raise RuntimeError('Public key unavailable')
        private = X25519PrivateKey.generate()
        key = derive_key(private, b64d(pk['public_key']))
        body = {'messages': [{'role':'user','content': report['synthetic_prompt_marker']+' Reply OK.'}],
                'max_tokens': 4, 'temperature': 0, 'stream': False,
                'chat_template_kwargs': {'enable_thinking':False}}
        event('encrypt_start')
        outer = seal_json(key, body, REQUEST_AAD)
        outer['client_public_key'] = b64e(public_bytes(private.public_key()))
        event('encrypt_end')
        status, encrypted = request(2, 'valid', 'POST', '/v1/encrypted/chat/completions', outer)
        event('decrypt_start')
        decrypted = open_json(key, encrypted, RESPONSE_AAD) if status == 200 else {}
        event('decrypt_end')
        report['synthetic_decrypted_response'] = decrypted
        check('encrypted_inference_authenticated_response', status == 200 and bool(decrypted.get('choices')))
        check('wire_response_envelope_only', set(encrypted) == {'version','nonce','ciphertext'})
        status, replay = request(3, 'replay', 'POST', '/v1/encrypted/chat/completions', outer)
        check('exact_replay_rejected', status == 400 and 'replayed encrypted request' in json.dumps(replay))
        # A fresh envelope ensures this tests authentication rather than replay lookup.
        tampered = seal_json(key, body, REQUEST_AAD)
        tampered['client_public_key'] = outer['client_public_key']
        raw = bytearray(b64d(tampered['ciphertext']))
        raw[0] ^= 1
        tampered['ciphertext'] = b64e(bytes(raw))
        status, _ = request(4, 'tamper', 'POST', '/v1/encrypted/chat/completions', tampered)
        check('fresh_ciphertext_tamper_rejected', status == 400)
        status, health = request(5, 'health_after', 'GET', '/healthz')
        check('healthy_idle_after', status == 200 and health.get('backend',{}).get('inflight_requests') == 0)
    except Exception as exc:
        report['error_type'] = type(exc).__name__
    finally:
        event('experiment_end')
        for s in sockets:
            s.close()
        report['capture'] = capture.stop()
        report['finished_ns'] = time.time_ns()
        with (directory/'client_result.json').open('x', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(json.dumps({'finished':True, 'tests':report['tests'], 'error_type':report.get('error_type')}), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('client','capture'))
    parser.add_argument('--directory', required=True)
    parser.add_argument('--server', required=True)
    parser.add_argument('--peer')
    parser.add_argument('--ports')
    parser.add_argument('--server-port',type=int,default=8000)
    args = parser.parse_args()
    if args.mode == 'client':
        client(args)
    else:
        c = Capture(Path(args.directory)/'cvm.pcap', args.peer, args.server, [int(x) for x in args.ports.split(',')],args.server_port)
        c.start()
        print('{"ready":true}', flush=True)
        # Parent closes stdin on disconnect; timeout outside bounds total lifetime.
        sys.stdin.readline()
        result = c.stop()
        with (Path(args.directory)/'capture_result.json').open('x') as f:
            json.dump(result, f, indent=2)
        print(json.dumps(result), flush=True)

if __name__ == '__main__':
    main()
