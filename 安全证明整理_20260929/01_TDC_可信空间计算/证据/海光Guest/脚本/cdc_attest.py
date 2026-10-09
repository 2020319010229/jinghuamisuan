#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CDC-03 双证明：GPU 远程证明（NVIDIA NRAS）+ CPU 侧 TD 报告接口核查

在 TDX 机密虚拟机内运行。产出：
  - GPU 证明 EAT token 及其关键声明
  - 策略校验结果
  - CPU 侧 TDX 报告接口（configfs-tsm）状态
"""
import base64
import json
import os
import secrets
import subprocess
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "/tmp/cdc_attest.json"

result = {"gpu": {}, "cpu": {}}

# ---------------- GPU 侧 ----------------
try:
    from nv_attestation_sdk import attestation

    nonce = secrets.token_hex(32)
    client = attestation.Attestation()
    client.set_name("tdx-cvm-b200")
    client.set_nonce(nonce)
    client.set_claims_version("2.0")
    client.add_verifier(
        attestation.Devices.GPU,
        attestation.Environment.REMOTE,
        "https://nras.attestation.nvidia.com/v3/attest/gpu",
        "",
    )
    evidence = client.get_evidence()
    ok = client.attest(evidence)
    token = client.get_token()

    result["gpu"]["nonce"] = nonce
    result["gpu"]["attest_result"] = bool(ok)
    result["gpu"]["token_len"] = len(str(token))

    # token 形如 [["JWT", "<eat>"], {"REMOTE_GPU_CLAIMS": "<jwt>"}]
    claims = {}
    try:
        parsed = json.loads(str(token).replace("'", '"'))
    except Exception:
        parsed = None

    def decode_jwt_payload(jwt_str):
        parts = jwt_str.split(".")
        if len(parts) < 2:
            return None
        pad = "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(parts[1] + pad))

    jwts = []
    s = str(token)
    # 粗暴提取所有看起来像 JWT 的串
    import re
    for m in re.finditer(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*", s):
        jwts.append(m.group(0))
    for j in jwts:
        try:
            p = decode_jwt_payload(j)
            if isinstance(p, dict):
                for k, v in p.items():
                    if k.startswith("x-nv") or k in (
                        "iss", "eat_nonce", "sub", "x-nvidia-overall-att-result"):
                        claims[k] = v
        except Exception:
            pass
    result["gpu"]["claims"] = claims
    result["gpu"]["jwt_count"] = len(jwts)

    policy = {
        "version": "2.0",
        "authorization-rules": {
            "type": "JWT",
            "x-nv-gpu-available": True,
            "x-nv-gpu-attestation-report-available": True,
            "x-nv-gpu-attestation-report-verified": True,
            "x-nv-gpu-measurements-match": True,
            "x-nv-gpu-nonce-match": True,
            "x-nv-gpu-cert-chain-verified": True,
        },
    }
    try:
        result["gpu"]["policy_validation"] = bool(
            client.validate_token(json.dumps(policy)))
    except Exception as e:
        result["gpu"]["policy_validation_error"] = str(e)

    with open("/tmp/gpu_eat_token.txt", "w") as f:
        f.write(str(token))
    result["gpu"]["token_file"] = "/tmp/gpu_eat_token.txt"

except Exception as e:
    import traceback
    result["gpu"]["error"] = str(e)
    result["gpu"]["trace"] = traceback.format_exc()[-800:]

# ---------------- CPU 侧 ----------------
def sh(c):
    return subprocess.run(c, shell=True, capture_output=True, text=True).stdout.strip()

result["cpu"]["tdx_guest_dev"] = os.path.exists("/dev/tdx_guest")
result["cpu"]["tsm_configfs"] = os.path.isdir("/sys/kernel/config/tsm/report")
result["cpu"]["cpuinfo_tdx_flag"] = "tdx_guest" in sh("grep -m1 flags /proc/cpuinfo")
result["cpu"]["dmesg_tdx"] = sh(
    "dmesg 2>/dev/null | grep -i -m3 -E 'tdx|Memory Encryption'").splitlines()
result["cpu"]["lsmod"] = sh("lsmod | grep -E '^tdx|^tsm'").splitlines()

# 尝试生成 TD 报告
rep_dir = "/sys/kernel/config/tsm/report/cdc0"
try:
    os.makedirs(rep_dir, exist_ok=True)
    result["cpu"]["provider"] = open(rep_dir + "/provider").read().strip()
    with open(rep_dir + "/inblob", "wb") as f:
        f.write(os.urandom(64))
    try:
        blob = open(rep_dir + "/outblob", "rb").read()
        result["cpu"]["quote_bytes"] = len(blob)
        if blob:
            open("/tmp/td_quote.bin", "wb").write(blob)
            result["cpu"]["quote_file"] = "/tmp/td_quote.bin"
    except Exception as e:
        result["cpu"]["quote_bytes"] = 0
        result["cpu"]["quote_error"] = str(e)
    result["cpu"]["generation"] = open(rep_dir + "/generation").read().strip()
except Exception as e:
    result["cpu"]["report_error"] = str(e)
finally:
    try:
        os.rmdir(rep_dir)
    except Exception:
        pass

with open(OUT, "w") as f:
    json.dump(result, f, indent=2, ensure_ascii=False)

print(json.dumps(result, indent=2, ensure_ascii=False)[:2600])
print("\nwrote", OUT)
