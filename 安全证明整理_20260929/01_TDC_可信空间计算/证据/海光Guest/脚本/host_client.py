#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TDC 模块2 —— 宿主侧客户端（数据方）

运行位置：宿主机（Host），代表把敏感 prompt 交给 TEE 的数据方。
连接方式：QEMU virtio-serial chardev 暴露的 unix socket。

本脚本同时承担"取证"职责：把信道上实际流过的**原始字节**落盘，
用于证明宿主在信道上只能看到密文。
"""
import argparse
import base64
import json
import os
import socket
import time

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

HKDF_INFO = b"tdc-module2-session-v1"


def b64e(b):
    return base64.b64encode(b).decode()


def b64d(s):
    return base64.b64decode(s)


class Channel:
    """带原始流量取证的 unix socket 封装。"""

    def __init__(self, path, capture_path=None):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(600)
        self.sock.connect(path)
        self.buf = b""
        self.cap = open(capture_path, "ab") if capture_path else None

    def send(self, obj):
        raw = (json.dumps(obj) + "\n").encode()
        if self.cap:
            self.cap.write(b"\n--- HOST->GUEST (%d bytes) ---\n" % len(raw))
            self.cap.write(raw)
            self.cap.flush()
        self.sock.sendall(raw)

    def recv(self):
        while b"\n" not in self.buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise RuntimeError("channel closed")
            if self.cap:
                self.cap.write(b"\n--- GUEST->HOST (%d bytes) ---\n" % len(chunk))
                self.cap.write(chunk)
                self.cap.flush()
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        return json.loads(line.decode())

    def close(self):
        if self.cap:
            self.cap.close()
        self.sock.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sock", default="/home/songyihong/tdc_module2/tdc.chan0.sock")
    ap.add_argument("--prompt", default="请用一句话解释什么是可信执行环境。")
    ap.add_argument("--capture", default="/home/songyihong/tdc_module2/channel_capture.bin")
    ap.add_argument("--json-out", default=None)
    args = ap.parse_args()

    print("[host] connecting", args.sock)
    ch = Channel(args.sock, args.capture)

    # 1) 取 Guest 公钥
    ch.send({"type": "hello"})
    hello = ch.recv()
    assert hello.get("type") == "pubkey", hello
    guest_pub = b64d(hello["pub"])
    print("[host] guest pubkey:", hello["pub"][:24] + "...", "model:", hello.get("model"))

    # 2) 本地生成临时密钥，ECDH 出会话密钥
    epriv = X25519PrivateKey.generate()
    epub = epriv.public_key().public_bytes_raw()
    shared = epriv.exchange(X25519PublicKey.from_public_bytes(guest_pub))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=HKDF_INFO).derive(shared)
    aes = AESGCM(key)
    print("[host] session key derived (X25519 + HKDF-SHA256)")

    # 3) 加密 prompt 发送
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, args.prompt.encode(), None)
    print("[host] plaintext prompt  :", args.prompt)
    print("[host] ciphertext on wire:", b64e(ct)[:64] + "...")
    t0 = time.time()
    ch.send({"type": "req", "epk": b64e(epub),
             "nonce": b64e(nonce), "ct": b64e(ct)})

    # 4) 收密文响应并解密
    resp = ch.recv()
    if resp.get("type") == "error":
        print("[host] GUEST ERROR:", resp.get("msg"))
        ch.close()
        return 1
    answer = aes.decrypt(b64d(resp["nonce"]), b64d(resp["ct"]), None).decode()
    rtt = time.time() - t0

    print("[host] ciphertext reply  :", resp["ct"][:64] + "...")
    print("[host] decrypted answer  :", answer)
    print("[host] guest stats       :", resp.get("stats"))
    print("[host] round trip        : %.2fs" % rtt)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump({
                "prompt": args.prompt,
                "answer": answer,
                "stats": resp.get("stats"),
                "rtt_s": round(rtt, 3),
                "wire_request_ct_b64": b64e(ct),
                "wire_response_ct_b64": resp["ct"],
                "guest_pub_b64": hello["pub"],
            }, f, ensure_ascii=False, indent=2)
        print("[host] wrote", args.json_out)

    ch.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
