# CDC-E2 GPU 远程证明（NVIDIA NRAS）

| 项目 | 内容 |
| --- | --- |
| 对应条目 | CDC-03 GPU-TEE 可信状态与远程证明；CDC-02 CPU 侧证明接口 |
| 地点 | B200 服务器 TDX 机密虚机内 |
| 时间 | 2026-09-24 |
| 结果 | GPU 证明通过；CPU 侧 TDREPORT 接口可用，TD Quote 签名待补 |

## 目的

让数据方在交付机密数据之前，能独立验证对端是一块运行正版驱动与 VBIOS、未被篡改、处于 CC 模式的 B200。

## 方法

在 CVM 内用 `nv-attestation-sdk` 生成新鲜 nonce，向 NVIDIA 官方证明服务 NRAS（`nras.attestation.nvidia.com`）发起 GPU 远程证明，保存返回的 EAT token 并解析声明。同时检查 CPU 侧 TDX 证明接口。脚本：`cdc_attest.py`。

## 结果

**GPU 证明**：`x-nvidia-overall-att-result = true`，EAT token 3055 字节，nonce `914d5ab6…f849d3`。

| 声明 | 值 |
| --- | --- |
| attestation-report-signature-verified（报告签名） | true |
| attestation-report-cert-chain-validated（证书链） | true |
| attestation-report-nonce-match（防重放） | true |
| driver-rim-signature-verified / cert-validated | true |
| vbios-rim-signature-verified / cert-validated | true |
| gpu-arch-check | true |
| attestation-warning | null |
| 驱动 / VBIOS 版本 | 610.57.04 / 97.00.D9.00.35 |

**CPU 侧**：

| 项 | 观测 |
| --- | --- |
| `/dev/tdx_guest` | 存在 |
| configfs-tsm provider | `tdx_guest` |
| 内核模块 | `tdx_guest`、`tsm` 已加载 |
| TD Quote | **0 字节**（宿主未部署 QGS 服务） |

## 证据文件

- `../证据/B200_TDX_CC/cdc_attest.json`
- `../证据/B200_TDX_CC/gpu_eat_token.txt`

## 说明

- `cdc_attest.json` 中另有一条本地策略校验记录 `policy_validation_error: 'overall-claims'`，原因未查明；NRAS 返回的总体结果与各项声明均为 true。补测 CPU 侧证明时应一并用正式策略文件重跑本地校验。
- 部署 tdx-qgs 并配置根证书后，可补齐 CPU 侧完整证明。
