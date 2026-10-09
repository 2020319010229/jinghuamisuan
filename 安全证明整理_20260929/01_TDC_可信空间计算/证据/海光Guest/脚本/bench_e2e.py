#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TDC 模块2 —— 端到端密态推理评测

按输入/输出 token 量做梯度爬坡，每条 query 内容互不相同（避免缓存命中
影响指标），记录每轮的端到端时延、Guest 内推理时延与加解密开销。
"""
import argparse
import base64
import json
import os
import socket
import statistics
import time

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

HKDF_INFO = b"tdc-module2-session-v1"
b64e = lambda b: base64.b64encode(b).decode()
b64d = lambda s: base64.b64decode(s)

# 梯度爬坡用例：输入长度递增，且每条内容唯一
CASES = [
    ("S1-短", "用一句话说明什么是同态加密。"),
    ("S2-短", "列出三种常见的对称加密算法名称。"),
    ("M1-中", "请解释可信执行环境与虚拟化隔离的区别，"
              "并说明各自适合的业务场景，控制在一百字以内。"),
    ("M2-中", "简要说明国密 SM4 算法与 AES 的差异，"
              "包括分组长度、密钥长度与典型应用领域，控制在一百字以内。"),
    ("L1-长", "假设一家金融机构要把风控模型部署到第三方算力平台，"
              "模型权重与客户数据都不能被平台方看到。请从密钥管理、"
              "数据传输、内存保护、远程证明四个方面，分条说明需要哪些"
              "技术手段，以及每一项手段防御的具体威胁。"),
    ("L2-长", "假设某医院要把病历文本交给外部大模型做结构化抽取，"
              "病历内容属于敏感个人信息。请从数据最小化、传输加密、"
              "运行时保护、审计留痕四个方面，分条说明合规落地方案，"
              "并指出每个环节最容易被忽略的风险点。"),
]


class Session:
    def __init__(self, sock_path):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.settimeout(900)
        self.s.connect(sock_path)
        self.buf = b""
        self.wire_bytes = 0

    def _send(self, obj):
        raw = (json.dumps(obj) + "\n").encode()
        self.wire_bytes += len(raw)
        self.s.sendall(raw)

    def _recv(self):
        while b"\n" not in self.buf:
            c = self.s.recv(65536)
            if not c:
                raise RuntimeError("closed")
            self.wire_bytes += len(c)
            self.buf += c
        line, self.buf = self.buf.split(b"\n", 1)
        return json.loads(line.decode())

    def handshake(self):
        self._send({"type": "hello"})
        h = self._recv()
        self.guest_pub = b64d(h["pub"])
        epriv = X25519PrivateKey.generate()
        self.epub = epriv.public_key().public_bytes_raw()
        shared = epriv.exchange(X25519PublicKey.from_public_bytes(self.guest_pub))
        key = HKDF(algorithm=hashes.SHA256(), length=32,
                   salt=None, info=HKDF_INFO).derive(shared)
        self.aes = AESGCM(key)
        return h

    def ask(self, prompt):
        t_enc0 = time.perf_counter()
        nonce = os.urandom(12)
        ct = self.aes.encrypt(nonce, prompt.encode(), None)
        t_enc = time.perf_counter() - t_enc0

        t0 = time.perf_counter()
        self._send({"type": "req", "epk": b64e(self.epub),
                    "nonce": b64e(nonce), "ct": b64e(ct)})
        r = self._recv()
        rtt = time.perf_counter() - t0
        if r.get("type") == "error":
            raise RuntimeError(r.get("msg"))

        t_dec0 = time.perf_counter()
        answer = self.aes.decrypt(b64d(r["nonce"]), b64d(r["ct"]), None).decode()
        t_dec = time.perf_counter() - t_dec0

        return answer, r.get("stats", {}), rtt, t_enc, t_dec

    def close(self):
        self.s.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sock", default="/home/songyihong/tdc_module2/tdc.chan0.sock")
    ap.add_argument("--out", default="/home/songyihong/tdc_module2/bench_result.json")
    ap.add_argument("--rounds", type=int, default=1)
    args = ap.parse_args()

    sess = Session(args.sock)
    h = sess.handshake()
    print("[bench] handshake ok, guest model =", h.get("model"))
    print()

    rows = []
    for rnd in range(args.rounds):
        for tag, prompt in CASES:
            label = tag if args.rounds == 1 else "%s#%d" % (tag, rnd + 1)
            # 保证每次 query 不一致，避免任何缓存命中
            uniq = "%s（本次请求编号 %s-%d）" % (prompt, label, int(time.time() * 1000) % 100000)
            try:
                ans, stats, rtt, t_enc, t_dec = sess.ask(uniq)
            except Exception as e:
                print("[bench] %-8s FAILED: %s" % (label, e))
                rows.append({"case": label, "error": str(e)})
                continue
            pt = stats.get("prompt_tokens", 0)
            gt = stats.get("gen_tokens", 0)
            infer = stats.get("latency_s", 0.0)
            tpot = (infer / gt * 1000) if gt else 0.0
            rows.append({
                "case": label,
                "prompt_chars": len(uniq),
                "prompt_tokens": pt,
                "gen_tokens": gt,
                "guest_infer_s": round(infer, 3),
                "e2e_rtt_s": round(rtt, 3),
                "crypto_overhead_ms": round((t_enc + t_dec) * 1000, 3),
                "tpot_ms": round(tpot, 1),
                "answer_preview": ans[:60].replace("\n", " "),
            })
            print("[bench] %-8s in=%3dtok out=%3dtok  guest=%6.2fs  e2e=%6.2fs  "
                  "TPOT=%6.1fms  crypto=%.3fms"
                  % (label, pt, gt, infer, rtt, tpot, (t_enc + t_dec) * 1000))

    sess.close()

    ok = [r for r in rows if "error" not in r]
    summary = {}
    if ok:
        summary = {
            "cases": len(ok),
            "total_gen_tokens": sum(r["gen_tokens"] for r in ok),
            "mean_e2e_s": round(statistics.mean(r["e2e_rtt_s"] for r in ok), 3),
            "mean_tpot_ms": round(statistics.mean(r["tpot_ms"] for r in ok), 1),
            "mean_crypto_overhead_ms": round(
                statistics.mean(r["crypto_overhead_ms"] for r in ok), 3),
            "crypto_share_of_e2e_pct": round(
                100 * statistics.mean(r["crypto_overhead_ms"] / 1000 / r["e2e_rtt_s"]
                                      for r in ok), 4),
            "wire_bytes_total": sess.wire_bytes,
        }
        print()
        print("[bench] summary:", json.dumps(summary, ensure_ascii=False))

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "summary": summary}, f,
                  ensure_ascii=False, indent=2)
    print("[bench] wrote", args.out)


if __name__ == "__main__":
    main()
