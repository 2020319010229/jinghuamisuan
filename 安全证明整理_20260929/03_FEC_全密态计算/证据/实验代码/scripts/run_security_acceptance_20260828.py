#!/usr/bin/env python3
"""Non-destructive security acceptance for the live Kunpeng OTP35B gateway."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

BASE = os.environ.get("OTP35_SECURITY_URL", "http://127.0.0.1:8000").rstrip("/")
VERSION = "otp35b-kunpeng-v1"
REQUEST_AAD = (VERSION + "/request").encode()
RESPONSE_AAD = (VERSION + "/response").encode()
ROOT = Path(os.environ.get("OTP35_ROOT", "/data/otp_c35"))
OUT = Path(os.environ.get("OTP35_SECURITY_OUT", str(ROOT / "results/security_acceptance_20260828")))
OUT.mkdir(parents=True, exist_ok=True)


def b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def b64d(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def http(method: str, path: str, value=None, timeout=30):
    data = None if value is None else json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"} if data else {})
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read()
            return response.status, raw, time.monotonic() - started
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), time.monotonic() - started


def derive(client: X25519PrivateKey, server_raw: bytes) -> bytes:
    shared = client.exchange(X25519PublicKey.from_public_bytes(server_raw))
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=VERSION.encode()).derive(shared)


def envelope(body: dict, server_raw: bytes, nonce: bytes | None = None):
    private = X25519PrivateKey.generate()
    pub = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key = derive(private, server_raw)
    nonce = nonce or os.urandom(12)
    raw = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()
    outer = {"version": VERSION, "client_public_key": b64e(pub), "nonce": b64e(nonce),
             "ciphertext": b64e(AESGCM(key).encrypt(nonce, raw, REQUEST_AAD))}
    return outer, key


tests = []
findings = []


def add(test_id, name, passed, evidence, severity=""):
    tests.append({"id": test_id, "name": name, "passed": bool(passed), "evidence": evidence,
                  "severity": severity})


run_started = time.time()

# Service and platform identity.
status, raw, elapsed = http("GET", "/healthz")
health = json.loads(raw) if status == 200 else {}
add("S01", "服务健康与密态模式", status == 200 and health.get("status") == "ok" and
    health.get("backend", {}).get("mode") == "shannon_rns_otp",
    {"http_status": status, "elapsed_ms": round(elapsed * 1000, 3), "response": health})

status, raw, _ = http("GET", "/v1/tee/info")
info = json.loads(raw) if status == 200 else {}
add("S02", "鲲鹏/双 Ascend 310P/TP2 运行身份", status == 200 and info.get("architecture") == "aarch64" and
    info.get("devices") == 2 and "TP=2" in info.get("parallelism", ""), info)

status, raw, _ = http("GET", "/v1/tee/public-key")
pk = json.loads(raw) if status == 200 else {}
server_raw = b64d(pk.get("public_key", "")) if status == 200 else b""
status2, raw2, _ = http("GET", "/v1/tee/public-key")
pk2 = json.loads(raw2) if status2 == 200 else {}
add("S03", "密钥协商算法与公钥长度", status == 200 and len(server_raw) == 32 and
    pk.get("algorithm") == "X25519+HKDF-SHA256+AES-256-GCM",
    {"algorithm": pk.get("algorithm"), "public_key_bytes": len(server_raw),
     "public_key_sha256": hashlib.sha256(server_raw).hexdigest()})
add("S04", "测试窗口内服务公钥稳定", pk.get("public_key") == pk2.get("public_key"),
    {"two_fetches_equal": pk.get("public_key") == pk2.get("public_key")})

key_path = ROOT / ".tee_x25519.key"
key_stat = key_path.stat() if key_path.exists() else None
key_mode = stat.S_IMODE(key_stat.st_mode) if key_stat else None
add("S05", "服务私钥文件权限", key_stat is not None and key_stat.st_size == 32 and key_mode == 0o600,
    {"path": str(key_path), "exists": key_stat is not None,
     "size": key_stat.st_size if key_stat else None,
     "mode": oct(key_mode) if key_mode is not None else None})

# Local cryptographic invariants and wire confidentiality.
marker = "BDSZ_MAGIC_20260828_7F3A91"
body = {"model": "qwen3.5-35b-a3b-otp-c", "prompt": "仅输出OK。" + marker,
        "max_tokens": 1, "stream": False, "temperature": 0}
outer, key = envelope(body, server_raw)
wire = json.dumps(outer, separators=(",", ":"))
forbidden = [marker, "仅输出OK", '"prompt"', '"messages"', '"input_ids"']
hits = [item for item in forbidden if item in wire]
add("S06", "请求线上封装不含明文和推理字段", not hits,
    {"wire_fields": sorted(outer), "wire_bytes": len(wire.encode()), "plaintext_hits": hits,
     "ciphertext_sha256": hashlib.sha256(b64d(outer["ciphertext"])).hexdigest()})

nonce_set = set()
cipher_set = set()
for _ in range(4096):
    sample, _ = envelope({"probe": "same-payload"}, server_raw)
    nonce_set.add(sample["nonce"])
    cipher_set.add(sample["ciphertext"])
add("S07", "4096 次请求 nonce 与密文唯一", len(nonce_set) == 4096 and len(cipher_set) == 4096,
    {"samples": 4096, "unique_nonces": len(nonce_set), "unique_ciphertexts": len(cipher_set)})

ct = bytearray(b64d(outer["ciphertext"]))
ct[-1] ^= 1
try:
    AESGCM(key).decrypt(b64d(outer["nonce"]), bytes(ct), REQUEST_AAD)
    local_tamper = False
except InvalidTag:
    local_tamper = True
try:
    AESGCM(key).decrypt(b64d(outer["nonce"]), b64d(outer["ciphertext"]), b"wrong-aad")
    local_aad = False
except InvalidTag:
    local_aad = True
add("S08", "本地 AES-GCM 篡改与错误 AAD 拒绝", local_tamper and local_aad,
    {"ciphertext_bitflip_rejected": local_tamper, "wrong_aad_rejected": local_aad})

# Live negative tests (no inference is reached).
tampered = dict(outer)
tampered["ciphertext"] = b64e(bytes(ct))
status, raw, elapsed = http("POST", "/v1/encrypted/chat/completions", tampered)
add("S09", "在线密文篡改拒绝", status == 400,
    {"http_status": status, "elapsed_ms": round(elapsed * 1000, 3),
     "error_sha256": hashlib.sha256(raw).hexdigest()})

bad_version, _ = envelope({"prompt": "x", "max_tokens": 1}, server_raw)
bad_version["version"] = "otp35b-kunpeng-v0"
status, raw, elapsed = http("POST", "/v1/encrypted/chat/completions", bad_version)
add("S10", "协议版本/AAD 降级拒绝", status == 400 and b"unsupported envelope version" in raw,
    {"http_status": status, "elapsed_ms": round(elapsed * 1000, 3), "reason_visible": b"unsupported envelope version" in raw})

bad_nonce, _ = envelope({"prompt": "x", "max_tokens": 1}, server_raw)
bad_nonce["nonce"] = b64e(os.urandom(8))
status, raw, elapsed = http("POST", "/v1/encrypted/chat/completions", bad_nonce)
add("S11", "非法 nonce 长度拒绝", status == 400 and b"nonce must be 12 bytes" in raw,
    {"http_status": status, "elapsed_ms": round(elapsed * 1000, 3), "reason_visible": b"nonce must be 12 bytes" in raw})

bad_peer, _ = envelope({"prompt": "x", "max_tokens": 1}, server_raw)
bad_peer["client_public_key"] = b64e(os.urandom(31))
status, raw, elapsed = http("POST", "/v1/encrypted/chat/completions", bad_peer)
add("S12", "非法 X25519 公钥长度拒绝", status == 400 and b"public key must be 32 bytes" in raw,
    {"http_status": status, "elapsed_ms": round(elapsed * 1000, 3), "reason_visible": b"public key must be 32 bytes" in raw})

# One real encrypted inference followed by an exact replay.
status, response_raw, inference_s = http("POST", "/v1/encrypted/chat/completions", outer, timeout=900)
response_outer = json.loads(response_raw) if status == 200 else {}
response_value = {}
response_ok = False
if status == 200:
    try:
        response_nonce = b64d(response_outer["nonce"])
        response_plain = AESGCM(key).decrypt(response_nonce, b64d(response_outer["ciphertext"]), RESPONSE_AAD)
        response_value = json.loads(response_plain)
        response_ok = response_outer.get("version") == VERSION and len(response_nonce) == 12 and bool(response_value.get("choices"))
    except Exception:
        response_ok = False
add("S13", "端到端加密推理与加密响应可认证解密", response_ok,
    {"http_status": status, "elapsed_s": round(inference_s, 3), "response_wire_fields": sorted(response_outer),
     "response_wire_has_choices": b'\"choices\"' in response_raw,
     "response_wire_has_content": b'\"content\"' in response_raw,
     "finish_reason": (response_value.get("choices") or [{}])[0].get("finish_reason") if response_value else None,
     "usage": response_value.get("usage") if response_value else None,
     "decrypted_response_sha256": hashlib.sha256(json.dumps(response_value, sort_keys=True, ensure_ascii=False).encode()).hexdigest() if response_value else None})

status, replay_raw, replay_s = http("POST", "/v1/encrypted/chat/completions", outer, timeout=30)
add("S14", "同一 client public key + nonce 重放拒绝", status == 400 and b"replayed encrypted request" in replay_raw,
    {"http_status": status, "elapsed_ms": round(replay_s * 1000, 3),
     "reason_visible": b"replayed encrypted request" in replay_raw})

# Exposure/fail-safe observations.
status, raw, elapsed = http("POST", "/v1/chat/completions", {"prompt": ""})
plaintext_exposed = status != 404
findings.append({"id": "F01", "severity": "HIGH", "name": "0.0.0.0 服务监听端口仍暴露明文推理路由",
                 "observed": plaintext_exposed, "evidence": {"http_status": status, "elapsed_ms": round(elapsed * 1000, 3)},
                 "recommendation": "生产入口关闭 /v1/chat/completions，或仅绑定 loopback/可信管理网并由 mTLS 反向代理限制；实际公网可达性还需结合边界防火墙确认。"})
add("S15", "未知路由默认拒绝", http("POST", "/v1/not-a-route", {"x": 1})[0] == 404,
    {"expected_status": 404})

# RNS mask CSPRNG, rejection sampling and zeroization executable on this machine.
binary = ROOT / "test_otp_security"
if binary.exists():
    proc = subprocess.run([str(binary)], cwd=str(ROOT), text=True, capture_output=True, timeout=120)
    rng_out = (proc.stdout + proc.stderr).strip()
    rng_ok = proc.returncode == 0 and "RNS_MOD_UNIFORM_PASS" in rng_out and "zeroize=PASS" in rng_out
else:
    proc = None
    rng_out = "binary missing"
    rng_ok = False
add("S16", "RNS CSPRNG 唯一性/均匀性/清零实测", rng_ok,
    {"returncode": proc.returncode if proc else None, "output": rng_out})

source = (ROOT / "otp_rng.h").read_text(encoding="utf-8", errors="replace") + "\n" + (ROOT / "q8_ops.c").read_text(encoding="utf-8", errors="replace")
source_checks = {"getrandom": "getrandom" in source, "rejection_sampling": "limit" in source and "% q" in source,
                 "secure_zero": "otp_secure_zero" in source,
                 "rns_mode": "q8_set_rns_mode" in source and "g_rns_mode" in source}
add("S17", "RNS 掩码生成与清零代码路径", all(source_checks.values()), source_checks)

passed = sum(1 for item in tests if item["passed"])
failed = len(tests) - passed
result = {
    "schema": "otp35b-security-acceptance-v1",
    "run_started_epoch": run_started,
    "run_finished_epoch": time.time(),
    "target": BASE,
    "machine": info,
    "summary": {"passed": passed, "failed": failed, "total": len(tests), "all_pass": failed == 0,
                "findings": len(findings)},
    "tests": tests,
    "findings": findings,
    "scope_notes": [
        "本轮为非破坏性接口、密码协议、CSPRNG/RNS 与运行配置验证。",
        "未执行 DoS、资源耗尽、固件攻击、物理攻击或微架构侧信道利用。",
        "virtCCA 启动属性由宿主机 libvirt/QEMU 证据独立采集；远程证明 quote 未在本脚本验证。"
    ]
}
path = OUT / "security_acceptance_raw.json"
path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps({"result_path": str(path), **result["summary"]}, ensure_ascii=False))
