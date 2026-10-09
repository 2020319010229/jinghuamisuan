# 方案二：机密空间计算（CDC）

> 架构：CPU-TEE + 支持 GPU-CC 的 GPU-TEE
> 核心主张：CPU 与 GPU 都处于经过验证的机密计算状态；CPU 内存、GPU 显存受保护；可被远程证明。
> 边界：结论只适用于本次验证的硬件、固件、驱动和安全模式组合；开发、调试或非机密模式不作为证明环境。

## 1. 在哪里做的

| 平台 | 硬件 / 软件 | 时间 | 用途 |
| --- | --- | --- | --- |
| B200 服务器（主平台） | 宿主 gpuhost：Xeon 8568Y+ 192 核 / 1885 GB / 8 × NVIDIA B200；Intel TDX 机密虚机（Ubuntu 24.04，OVMF.inteltdx）；1 张 B200 以 CC 模式 vfio 透传进 CVM；驱动 610.57.04，VBIOS 97.00.D9.00.35 | 2026-09-23 ~ 09-24 | 双 TEE 状态、GPU 远程证明、宿主内存取证 |
| 鲲鹏 + 昇腾 310P（前置核查） | Atlas 300V Pro / Ascend 310P3 | 2026-09-18 | 核查该平台是否具备 GPU-CC 能力（结论：不具备，因此 CDC 改在 B200 上做） |

## 2. 实验清单

| 实验 | 对应计划书条目 | 平台 | 结果 |
| --- | --- | --- | --- |
| [CDC-E0 昇腾 310P 机密计算能力核查](实验/CDC-E0_昇腾310P机密计算能力核查.md) | CDC-01（平台选择依据） | 鲲鹏 + 310P | 平台不具备 GPU-CC |
| [CDC-E1 CPU 与 GPU 双 TEE 状态核验](实验/CDC-E1_CPU与GPU双TEE状态核验.md) | CDC-01、CDC-02（状态部分） | B200 | 通过：CC=ON / PRODUCTION / Ready；TDX 激活 |
| [CDC-E2 GPU 远程证明（NVIDIA NRAS）](实验/CDC-E2_GPU远程证明NRAS.md) | CDC-03 | B200 | 通过：签名、证书链、nonce、度量值匹配均为 true |
| [CDC-E3 宿主内存取证（双 canary）](实验/CDC-E3_宿主内存取证_双canary.md) | CDC-05（CPU 内存部分） | B200 | 通过：宿主扫描 16.66 GB，纯内存 canary 0 命中 |

## 3. 本方向结论

| 计划书条目 | 判定 | 依据 |
| --- | --- | --- |
| CDC-01 GPU-CC 兼容性与正式模式确认 | 通过 | E1：CVM 内 `CC State: ON`、`CC Environment: PRODUCTION`、`Ready`；TDX BIOS 已启用 |
| CDC-02 CPU-TEE 可信状态 | 通过（状态）/ 证明签名待补 | E1：`tdx: Guest detected`、`Memory Encryption Features active: Intel TDX`；TD Quote 因宿主未部署 QGS 读出 0 字节 |
| CDC-03 GPU-TEE 可信状态与远程证明 | 通过 | E2：NRAS 证明通过，EAT token 3055 字节，关键声明全部为 true |
| CDC-05 CPU 内存与 GPU 显存隔离 | 通过（CPU 内存实测 + 显存保护状态） | E3：纯内存 canary 宿主 0 命中（阳性对照 24,105）；E1：显存 Protected 177 GB / Unprotected 0；宿主侧该卡已绑定 vfio-pci，宿主 `nvidia-smi` 只剩 7 张卡 |

**要一起写明的边界**：Guest 主动写入模拟设备（磁盘、网络）的数据经共享 DMA 页，宿主可见（E3 实验一已实测定位）。这是 TDX 的设计行为，这类数据需要靠传输层加密保护。

## 4. 证据目录

```
证据/
├── B200_TDX_CC/        cvm_evidence.txt、host_evidence.txt、cvm-console.log、cdc_attest.json、gpu_eat_token.txt、
│                       cdc_mem_forensics_v3.json、cdc_mem_forensics_pure.json、memtest_raw_logs.txt、bench_cc_on.json
├── B200_脚本/          cdc_attest.py、cdc_mem_forensics.py、cdc_gpu_bench.py
├── 昇腾310P_平台核查/  cdc01_platform/（npu_security_capability.txt、probe.sh）、复测_cdc/result.json
└── 原始报告/           CDC_B200_机密计算安全验证报告.htm
```

> 编号说明：原始报告《CDC_B200_机密计算安全验证报告》里的 CDC-01~06 是报告内部编号，与计划书的 CDC-01~09 不一一对应。本目录统一按**计划书编号**对应。
