#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TDC 模块2 —— Guest 内密态推理服务端（含全链路打点）

运行位置：TDC Guest 虚拟机内部（openEuler rootfs）
通信信道：virtio-serial 字符设备（宿主侧表现为一个 unix socket）

安全设计：
  1. 会话密钥由 X25519 ECDH 在 Guest 内协商，私钥只存在于 Guest 内存，
     从不写盘、从不经过信道传输。
  2. 客户端 prompt 以 AES-256-GCM 密文进入 Guest，在 Guest 内解密后才
     交给模型；推理结果在 Guest 内加密后才离开。
  3. 宿主（Host）在信道上只能观察到密文、nonce、tag 与一次性公钥。

打点设计（Guest 侧五段，配合客户端四段构成九段瀑布）：
  G1 decrypt   解密请求
  G2 tokenize  分词与对话模板
  G3 prefill   首个 token 产出（TTFT 的模型部分）
  G4 decode    其余 token 逐个生成
  G5 encrypt   加密响应
  另回传 guest_recv_wall / guest_send_wall 两个墙钟时刻，
  供客户端在时钟校准后拆分上下行传输耗时。

协议（NDJSON，一行一个 JSON 对象）：
  <- {"type":"hello"}
  -> {"type":"pubkey","pub":<b64 X25519 公钥>,"model":<名称>}
  <- {"type":"ping","t1":<客户端发出墙钟>}
  -> {"type":"pong","t2":<Guest 收到>,"t3":<Guest 发出>}
  <- {"type":"req","epk":<b64>,"nonce":<b64>,"ct":<b64>,"max_new_tokens":<int>}
  -> {"type":"resp","nonce":<b64>,"ct":<b64>,"stats":{...},"timing":{...}}
"""
import base64
import json
import os
import sys
import time

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

MODEL_DIR = os.environ.get("TDC_MODEL", "/opt/tdc/model")
PORT_DEV = os.environ.get("TDC_PORT", "/dev/virtio-ports/tdc.chan0")
HKDF_INFO = b"tdc-module2-session-v1"
MAX_NEW_TOKENS = int(os.environ.get("TDC_MAX_NEW_TOKENS", "64"))


def log(*a):
    print("[guest]", *a, flush=True)


def b64e(b):
    return base64.b64encode(b).decode()


def b64d(s):
    return base64.b64decode(s)


def ms(t0, t1):
    return round((t1 - t0) * 1000, 3)


def derive_key(priv, peer_pub_bytes):
    """X25519 ECDH + HKDF-SHA256 -> 32 字节 AES-GCM 会话密钥。"""
    shared = priv.exchange(X25519PublicKey.from_public_bytes(peer_pub_bytes))
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=HKDF_INFO
    ).derive(shared)


class Engine:
    """延迟加载的 Qwen 推理引擎，prefill 与 decode 分开计时。"""

    def __init__(self, model_dir):
        self.model_dir = model_dir
        self.tok = None
        self.model = None
        self.manual_kv = True

    def load(self):
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer

        t0 = time.time()
        log("loading tokenizer/model from", self.model_dir)
        self.tok = AutoTokenizer.from_pretrained(self.model_dir)
        self.model = AutoModelForCausalLM.from_pretrained(
            self.model_dir, dtype=torch.float32
        )
        self.model.eval()
        self.torch = torch
        log("model ready in %.1fs" % (time.time() - t0))

    def _new_cache(self):
        """兼容不同 transformers 版本的 KV cache 构造。"""
        try:
            from transformers import DynamicCache
            return DynamicCache()
        except Exception:
            try:
                from transformers.cache_utils import DynamicCache
                return DynamicCache()
            except Exception:
                return None

    def generate(self, prompt, max_new_tokens=MAX_NEW_TOKENS):
        """返回 (answer, stats, timing_parts)。timing_parts 内含 tokenize/prefill/decode。"""
        if self.model is None:
            self.load()
        torch = self.torch

        # --- G2 tokenize ---
        t_tok0 = time.perf_counter()
        msgs = [{"role": "user", "content": prompt}]
        text = self.tok.apply_chat_template(
            msgs, tokenize=False, add_generation_prompt=True
        )
        enc = self.tok([text], return_tensors="pt")
        input_ids = enc["input_ids"]
        attn = enc.get("attention_mask")
        t_tok1 = time.perf_counter()

        eos_ids = set()
        for e in (self.tok.eos_token_id, getattr(self.model.config, "eos_token_id", None)):
            if isinstance(e, int):
                eos_ids.add(e)
            elif isinstance(e, (list, tuple)):
                eos_ids.update(int(x) for x in e)

        gen_ids = []
        t_pre0 = t_pre1 = t_dec1 = 0.0

        if self.manual_kv:
            try:
                cache = self._new_cache()
                # --- G3 prefill：跑完整个 prompt，拿到第一个新 token ---
                t_pre0 = time.perf_counter()
                with torch.no_grad():
                    out = self.model(input_ids=input_ids, attention_mask=attn,
                                     past_key_values=cache, use_cache=True)
                past = out.past_key_values
                next_id = out.logits[:, -1, :].argmax(-1, keepdim=True)
                t_pre1 = time.perf_counter()
                gen_ids.append(int(next_id[0, 0]))

                # --- G4 decode：其余 token ---
                cur_attn = attn
                for _ in range(max_new_tokens - 1):
                    if gen_ids[-1] in eos_ids:
                        break
                    if cur_attn is not None:
                        cur_attn = torch.cat(
                            [cur_attn, torch.ones((1, 1), dtype=cur_attn.dtype)], dim=1)
                    with torch.no_grad():
                        out = self.model(input_ids=next_id, attention_mask=cur_attn,
                                         past_key_values=past, use_cache=True)
                    past = out.past_key_values
                    next_id = out.logits[:, -1, :].argmax(-1, keepdim=True)
                    gen_ids.append(int(next_id[0, 0]))
                t_dec1 = time.perf_counter()
            except Exception as e:
                log("manual KV path failed (%s); falling back to generate()" % e)
                self.manual_kv = False
                gen_ids = []

        if not self.manual_kv:
            # 回退路径：prefill 与 decode 无法拆分，合并记在 decode 上
            t_pre0 = t_pre1 = time.perf_counter()
            with torch.no_grad():
                out = self.model.generate(**enc, max_new_tokens=max_new_tokens,
                                          do_sample=False)
            gen_ids = [int(x) for x in out[0][input_ids.shape[1]:]]
            t_dec1 = time.perf_counter()

        # 截断 eos 之后的内容
        clean = []
        for t in gen_ids:
            if t in eos_ids:
                break
            clean.append(t)
        answer = self.tok.decode(clean, skip_special_tokens=True)

        n_gen = len(gen_ids)
        decode_ms = ms(t_pre1, t_dec1)
        stats = {
            "prompt_tokens": int(input_ids.shape[1]),
            "gen_tokens": n_gen,
            "latency_s": round(t_dec1 - t_tok0, 3),
        }
        timing = {
            "tokenize_ms": ms(t_tok0, t_tok1),
            "prefill_ms": ms(t_pre0, t_pre1),
            "decode_ms": decode_ms,
            "decode_tokens": max(n_gen - 1, 0),
            "tpot_ms": round(decode_ms / max(n_gen - 1, 1), 3),
            "split_mode": "manual_kv" if self.manual_kv else "generate_fallback",
        }
        return answer, stats, timing


def open_channel(path):
    """打开 virtio-serial 端口，返回可读写的二进制文件对象。"""
    for i in range(60):
        if os.path.exists(path):
            break
        time.sleep(1)
    else:
        raise RuntimeError("channel device not found: %s" % path)
    return os.fdopen(os.open(path, os.O_RDWR), "r+b", buffering=0)


def main():
    log("boot; python", sys.version.split()[0])
    log("channel", PORT_DEV)

    priv = X25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes_raw()
    log("ephemeral X25519 keypair generated in-guest (private key never leaves)")

    engine = Engine(MODEL_DIR)
    engine.load()

    ch = open_channel(PORT_DEV)
    log("channel open, waiting for requests")

    buf = b""
    while True:
        chunk = ch.read(4096)
        if not chunk:
            time.sleep(0.05)
            continue
        t_recv_wall = time.time()
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line.decode())
            except Exception as e:
                log("bad json:", e)
                continue

            mtype = msg.get("type")

            if mtype == "hello":
                resp = {
                    "type": "pubkey",
                    "pub": b64e(pub_bytes),
                    "model": os.path.basename(MODEL_DIR.rstrip("/")),
                }
                ch.write((json.dumps(resp) + "\n").encode())
                log("sent pubkey")

            elif mtype == "ping":
                # 时钟校准：回传 Guest 侧收到与发出的墙钟时刻
                resp = {"type": "pong", "t2": t_recv_wall, "t3": time.time()}
                ch.write((json.dumps(resp) + "\n").encode())

            elif mtype == "req":
                try:
                    # --- G1 decrypt ---
                    t_dec0 = time.perf_counter()
                    key = derive_key(priv, b64d(msg["epk"]))
                    aes = AESGCM(key)
                    plaintext = aes.decrypt(
                        b64d(msg["nonce"]), b64d(msg["ct"]), None
                    ).decode()
                    t_dec1 = time.perf_counter()
                    log("decrypted request (%d chars) in-guest" % len(plaintext))

                    mnt = int(msg.get("max_new_tokens", MAX_NEW_TOKENS))
                    answer, stats, timing = engine.generate(plaintext, mnt)
                    log("generated %d tokens (prefill %.1fms, decode %.1fms)"
                        % (stats["gen_tokens"], timing["prefill_ms"],
                           timing["decode_ms"]))

                    # --- G5 encrypt ---
                    t_enc0 = time.perf_counter()
                    nonce = os.urandom(12)
                    ct = aes.encrypt(nonce, answer.encode(), None)
                    t_enc1 = time.perf_counter()

                    timing["decrypt_ms"] = ms(t_dec0, t_dec1)
                    timing["encrypt_ms"] = ms(t_enc0, t_enc1)
                    timing["guest_recv_wall"] = t_recv_wall
                    timing["guest_send_wall"] = time.time()
                    timing["guest_total_ms"] = round(
                        (timing["guest_send_wall"] - t_recv_wall) * 1000, 3)

                    resp = {
                        "type": "resp",
                        "nonce": b64e(nonce),
                        "ct": b64e(ct),
                        "stats": stats,
                        "timing": timing,
                    }
                except Exception as e:
                    resp = {"type": "error", "msg": str(e)}
                    log("error:", e)
                ch.write((json.dumps(resp) + "\n").encode())

            else:
                log("unknown type:", mtype)


if __name__ == "__main__":
    main()
