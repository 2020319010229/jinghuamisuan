#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TDC 模块2 —— 端侧全链路九段打点

把端到端时延拆成九段，定位每一毫秒花在哪：

  C1 client_encrypt   客户端加密
  N1 uplink           上行传输（宿主 → Guest，只走密文）
  G1 guest_decrypt    Guest 内解密
  G2 tokenize         分词与对话模板
  G3 prefill          首 token 产出（TTFT 的模型部分）
  G4 decode           其余 token 逐个生成
  G5 guest_encrypt    Guest 内加密
  N2 downlink         下行传输（Guest → 宿主，只走密文）
  C2 client_decrypt   客户端解密

上下行需要跨 Guest/Host 两个时钟，因此先做 NTP 式时钟校准：
多轮 ping/pong 取往返延迟最小的一轮估计时钟偏移，再据此拆分。
同时给出不依赖校准的可靠量（端到端 RTT、Guest 内总耗时、信道往返开销），
便于交叉核对。
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

CASES = [
    ("S1", "用一句话说明什么是同态加密。"),
    ("S2", "列出三种常见的对称加密算法名称。"),
    ("M1", "请解释可信执行环境与虚拟化隔离的区别，并说明各自适合的业务场景，控制在一百字以内。"),
    ("M2", "简要说明国密 SM4 算法与 AES 的差异，包括分组长度、密钥长度与典型应用领域，控制在一百字以内。"),
    ("L1", "假设一家金融机构要把风控模型部署到第三方算力平台，模型权重与客户数据都不能被平台方看到。"
           "请从密钥管理、数据传输、内存保护、远程证明四个方面，分条说明需要哪些技术手段，"
           "以及每一项手段防御的具体威胁。"),
    ("L2", "假设某医院要把病历文本交给外部大模型做结构化抽取，病历内容属于敏感个人信息。"
           "请从数据最小化、传输加密、运行时保护、审计留痕四个方面，分条说明合规落地方案，"
           "并指出每个环节最容易被忽略的风险点。"),
]


class Session:
    def __init__(self, sock_path, capture=None):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.settimeout(900)
        self.s.connect(sock_path)
        self.buf = b""
        self.wire_up = 0
        self.wire_down = 0
        self.cap = open(capture, "ab") if capture else None
        self.offset = 0.0          # Guest 时钟 - 客户端时钟
        self.chan_rtt_ms = None    # 空载荷信道往返

    def _send(self, obj):
        raw = (json.dumps(obj) + "\n").encode()
        self.wire_up += len(raw)
        if self.cap:
            self.cap.write(b"\n--- HOST->GUEST (%d bytes) ---\n" % len(raw))
            self.cap.write(raw); self.cap.flush()
        self.s.sendall(raw)
        return len(raw)

    def _recv(self):
        while b"\n" not in self.buf:
            c = self.s.recv(65536)
            if not c:
                raise RuntimeError("channel closed")
            self.wire_down += len(c)
            if self.cap:
                self.cap.write(b"\n--- GUEST->HOST (%d bytes) ---\n" % len(c))
                self.cap.write(c); self.cap.flush()
            self.buf += c
        line, self.buf = self.buf.split(b"\n", 1)
        return json.loads(line.decode())

    # ---------- 时钟校准 ----------
    def calibrate(self, rounds=12):
        best = None
        samples = []
        for _ in range(rounds):
            t1 = time.time()
            self._send({"type": "ping", "t1": t1})
            r = self._recv()
            t4 = time.time()
            if r.get("type") != "pong":
                continue
            t2, t3 = r["t2"], r["t3"]
            delay = (t4 - t1) - (t3 - t2)          # 纯网络往返
            offset = ((t2 - t1) + (t3 - t4)) / 2.0  # Guest 相对客户端的偏移
            samples.append(delay)
            if best is None or delay < best[0]:
                best = (delay, offset)
            time.sleep(0.01)
        if best:
            self.chan_rtt_ms = round(best[0] * 1000, 3)
            self.offset = best[1]
        return {
            "rounds": rounds,
            "chan_rtt_ms_min": self.chan_rtt_ms,
            "chan_rtt_ms_median": round(statistics.median(samples) * 1000, 3) if samples else None,
            "clock_offset_ms": round(self.offset * 1000, 3),
        }

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

    # ---------- 一次带打点的请求 ----------
    def ask(self, prompt, max_new_tokens=64):
        # C1 客户端加密
        c1_0 = time.perf_counter()
        nonce = os.urandom(12)
        ct = self.aes.encrypt(nonce, prompt.encode(), None)
        c1 = (time.perf_counter() - c1_0) * 1000

        t1 = time.time()
        rtt0 = time.perf_counter()
        up_bytes = self._send({"type": "req", "epk": b64e(self.epub),
                               "nonce": b64e(nonce), "ct": b64e(ct),
                               "max_new_tokens": max_new_tokens})
        r = self._recv()
        rtt = (time.perf_counter() - rtt0) * 1000
        t4 = time.time()
        if r.get("type") == "error":
            raise RuntimeError(r.get("msg"))

        # C2 客户端解密
        c2_0 = time.perf_counter()
        answer = self.aes.decrypt(b64d(r["nonce"]), b64d(r["ct"]), None).decode()
        c2 = (time.perf_counter() - c2_0) * 1000

        tm = r.get("timing", {})
        st = r.get("stats", {})
        t2 = tm.get("guest_recv_wall")
        t3 = tm.get("guest_send_wall")

        # 用校准后的偏移拆上下行
        if t2 and t3:
            uplink = (t2 - t1 - self.offset) * 1000
            downlink = (t4 - t3 + self.offset) * 1000
        else:
            uplink = downlink = None
        guest_total = tm.get("guest_total_ms")

        # 不依赖时钟校准的可靠量：信道总开销 = RTT - Guest 内总耗时
        chan_total = (rtt - guest_total) if guest_total is not None else None
        # 负值说明时钟或计时噪声，夹到 0
        if uplink is not None and uplink < 0:
            uplink = 0.0
        if downlink is not None and downlink < 0:
            downlink = 0.0

        seg = {
            "C1_client_encrypt_ms": round(c1, 3),
            "N1_uplink_ms": round(uplink, 3) if uplink is not None else None,
            "G1_guest_decrypt_ms": tm.get("decrypt_ms"),
            "G2_tokenize_ms": tm.get("tokenize_ms"),
            "G3_prefill_ms": tm.get("prefill_ms"),
            "G4_decode_ms": tm.get("decode_ms"),
            "G5_guest_encrypt_ms": tm.get("encrypt_ms"),
            "N2_downlink_ms": round(downlink, 3) if downlink is not None else None,
            "C2_client_decrypt_ms": round(c2, 3),
        }
        aux = {
            "e2e_rtt_ms": round(rtt, 3),
            "guest_total_ms": guest_total,
            "channel_total_ms": round(chan_total, 3) if chan_total is not None else None,
            "prompt_tokens": st.get("prompt_tokens"),
            "gen_tokens": st.get("gen_tokens"),
            "decode_tokens": tm.get("decode_tokens"),
            "ttft_ms": round(
                (c1 + (uplink or 0) + (tm.get("decrypt_ms") or 0)
                 + (tm.get("tokenize_ms") or 0) + (tm.get("prefill_ms") or 0)), 3),
            "tpot_ms": tm.get("tpot_ms"),
            "split_mode": tm.get("split_mode"),
            "wire_request_bytes": up_bytes,
        }
        return answer, seg, aux

    def close(self):
        if self.cap:
            self.cap.close()
        self.s.close()


SEG_LABEL = [
    ("C1_client_encrypt_ms", "C1 客户端加密", "client"),
    ("N1_uplink_ms",         "N1 上行传输",   "wire"),
    ("G1_guest_decrypt_ms",  "G1 Guest解密",  "guest"),
    ("G2_tokenize_ms",       "G2 分词",       "guest"),
    ("G3_prefill_ms",        "G3 prefill",    "model"),
    ("G4_decode_ms",         "G4 decode",     "model"),
    ("G5_guest_encrypt_ms",  "G5 Guest加密",  "guest"),
    ("N2_downlink_ms",       "N2 下行传输",   "wire"),
    ("C2_client_decrypt_ms", "C2 客户端解密", "client"),
]


def print_waterfall(seg, total):
    width = 46
    for key, label, _ in SEG_LABEL:
        v = seg.get(key) or 0.0
        n = int(round(v / total * width)) if total > 0 else 0
        bar = "#" * max(n, 1) if v > 0 else ""
        pct = (v / total * 100) if total > 0 else 0
        print("    %-14s %9.3f ms  %5.2f%%  %s" % (label, v, pct, bar))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sock", default="/home/songyihong/tdc_module2/tdc.chan0.sock")
    ap.add_argument("--out", default="/home/songyihong/tdc_module2/waterfall_result.json")
    ap.add_argument("--capture", default=None)
    ap.add_argument("--max-new-tokens", type=int, default=64)
    ap.add_argument("--repeat", type=int, default=1)
    args = ap.parse_args()

    sess = Session(args.sock, args.capture)
    h = sess.handshake()
    print("[wf] handshake ok, model =", h.get("model"))

    cal = sess.calibrate()
    print("[wf] clock calibration:", json.dumps(cal, ensure_ascii=False))
    print()

    rows = []
    for rep in range(args.repeat):
        for tag, prompt in CASES:
            label = tag if args.repeat == 1 else "%s#%d" % (tag, rep + 1)
            uniq = "%s（请求编号 %s-%d）" % (prompt, label, int(time.time() * 1000) % 100000)
            try:
                ans, seg, aux = sess.ask(uniq, args.max_new_tokens)
            except Exception as e:
                print("[wf] %-4s FAILED: %s" % (label, e))
                rows.append({"case": label, "error": str(e)})
                continue
            total = aux["e2e_rtt_ms"] + seg["C1_client_encrypt_ms"] + seg["C2_client_decrypt_ms"]
            print("[wf] %-4s  in=%3d out=%3d  e2e=%8.1fms  TTFT=%7.1fms  TPOT=%6.1fms"
                  % (label, aux["prompt_tokens"] or 0, aux["gen_tokens"] or 0,
                     total, aux["ttft_ms"], aux["tpot_ms"] or 0))
            print_waterfall(seg, total)
            print()
            rows.append({"case": label, "segments": seg, "aux": aux,
                         "answer_preview": ans[:50].replace("\n", " ")})

    ok = [r for r in rows if "error" not in r]
    summary = {}
    if ok:
        def mean_of(k):
            vals = [r["segments"][k] for r in ok if r["segments"].get(k) is not None]
            return round(statistics.mean(vals), 3) if vals else None
        totals = [r["aux"]["e2e_rtt_ms"] + r["segments"]["C1_client_encrypt_ms"]
                  + r["segments"]["C2_client_decrypt_ms"] for r in ok]
        mean_total = statistics.mean(totals)
        seg_mean = {k: mean_of(k) for k, _, _ in SEG_LABEL}
        crypto = sum((seg_mean[k] or 0) for k in
                     ("C1_client_encrypt_ms", "G1_guest_decrypt_ms",
                      "G5_guest_encrypt_ms", "C2_client_decrypt_ms"))
        wire = sum((seg_mean[k] or 0) for k in ("N1_uplink_ms", "N2_downlink_ms"))
        model = sum((seg_mean[k] or 0) for k in ("G3_prefill_ms", "G4_decode_ms"))
        summary = {
            "cases": len(ok),
            "mean_total_ms": round(mean_total, 3),
            "segment_mean_ms": seg_mean,
            "group_ms": {"crypto": round(crypto, 3), "wire": round(wire, 3),
                         "model": round(model, 3),
                         "tokenize": seg_mean["G2_tokenize_ms"]},
            "group_pct": {
                "crypto": round(crypto / mean_total * 100, 4),
                "wire": round(wire / mean_total * 100, 4),
                "model": round(model / mean_total * 100, 4),
            },
            "mean_ttft_ms": round(statistics.mean(r["aux"]["ttft_ms"] for r in ok), 3),
            "mean_tpot_ms": round(statistics.mean(
                r["aux"]["tpot_ms"] for r in ok if r["aux"].get("tpot_ms")), 3),
            "calibration": cal,
        }
        print("[wf] ---- 平均分组占比 ----")
        print("     密码学(C1+G1+G5+C2) %8.3f ms  %6.3f%%" % (crypto, summary["group_pct"]["crypto"]))
        print("     信道(N1+N2)         %8.3f ms  %6.3f%%" % (wire, summary["group_pct"]["wire"]))
        print("     模型(G3+G4)         %8.3f ms  %6.3f%%" % (model, summary["group_pct"]["model"]))
        print("     端到端平均          %8.3f ms" % mean_total)

    sess.close()
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "summary": summary}, f, ensure_ascii=False, indent=2)
    print("\n[wf] wrote", args.out)


if __name__ == "__main__":
    main()
