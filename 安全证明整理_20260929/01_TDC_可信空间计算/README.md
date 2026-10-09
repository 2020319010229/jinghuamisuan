# 方案一：可信空间计算（TDC）

> 架构：CPU 机密虚拟机（CPU-TEE）+ 通用加速卡原生直通
> 核心主张：输入数据与 CPU 侧明文处理位于 CPU 机密域；CPU 内存受保护、地址空间隔离；加速卡独占直通。
> 边界：通用加速卡不是 GPU-TEE。本方向不宣称显存、CPU—加速卡总线具备密码学机密性，也不表述为全链路密态。

## 1. 在哪里做的

| 平台 | 硬件 / 软件 | 时间 | 用途 |
| --- | --- | --- | --- |
| 鲲鹏 virtCCA（主平台） | 鲲鹏 920 + 2 × Atlas 300V Pro（Ascend 310P3，44 GB/卡）；CVM 为 virtCCA 机密虚机（`kvm-type=cvm` + `tmm-guest`）；两卡 vfio-pci 直通；模型 Qwen3.5-35B-A3B W8A8 | 2026-09-16 ~ 09-18 | TDC 可信状态、内存反向读取、直通独占、设备残留 |
| 海光 C86（补充平台） | Hygon C86 128 核 / 503 GB，openEuler 24.03，QEMU 8.2.0 + KVM；Guest 8 vCPU / 8 GB；模型 Qwen2.5-0.5B-Instruct | 2026-09-23 | Guest 内端到端密态推理（传输与数据路径） |

## 2. 实验清单

| 实验 | 对应计划书条目 | 平台 | 结果 |
| --- | --- | --- | --- |
| [TDC-E1 机密虚机状态与远程证明负例](实验/TDC-E1_机密虚机状态与远程证明负例.md) | TDC-01、TDC-02、G-02 | 鲲鹏 | 通过（证明负例 7/7） |
| [TDC-E2 宿主反向读取 CVM 内存](实验/TDC-E2_宿主反向读取CVM内存.md) | TDC-03 | 鲲鹏 | 通过（130.39 GB 读取，植入标记 0 命中） |
| [TDC-E3 加速卡直通独占与非授权访问](实验/TDC-E3_加速卡直通独占与非授权访问.md) | TDC-04、TDC-05 | 鲲鹏 | 通过（8/8 检查项） |
| [TDC-E4 设备内存跨进程残留](实验/TDC-E4_设备内存跨进程残留.md) | TDC-05 | 鲲鹏 | 通过（256 MB 读回非零字节 0） |
| [TDC-E5 海光 Guest 端到端密态推理](实验/TDC-E5_海光Guest端到端密态推理.md) | TDC-06（传输与数据路径） | 海光 | 通过（信道 1039 字节明文 0 命中） |

## 3. 本方向结论

| 计划书条目 | 判定 | 依据 |
| --- | --- | --- |
| TDC-01 架构与可信边界确认 | 通过 | E1：qemu 命令行实证 virtCCA 机密虚机、两卡 vfio 直通 |
| TDC-02 CPU-TEE 可信状态与远程证明 | 通过（验证策略口径） | E1：错误 challenge / 错误度量 / 签名篡改 / 缺设备证书全部被拒 |
| TDC-03 CPU 内存加密与地址空间隔离 | 通过 | E2：宿主读 CVM 内存 97.16%，运行时植入标记 0 命中，阳性对照成立 |
| TDC-04 非授权访问（宿主侧、CVM 内非特权用户） | 通过 | E3：宿主无设备节点、BAR 读 0 字节，CVM 非特权用户被拒 |
| TDC-05 加速卡直通独占与清理 | 通过 | E3 + E4：每个 IOMMU 组 1 个设备；跨进程残留 0 字节 |
| TDC-06 数据路径验证 | 通过 | E5：信道只见密文，解密与推理发生在 Guest 内；鲲鹏平台的网络抓包见 [FEC-E1](../03_FEC_全密态计算/实验/FEC-E1_网络抓包_网关与SDK.md) |

**适用范围**：TDC-03 的内存保护结论只适用于鲲鹏 virtCCA 平台。海光平台本次 CSV 内存加密未启用，只证明了传输与数据路径（E5），不引用为内存保护证据。

## 4. 证据目录

```
证据/
├── 鲲鹏virtCCA/        attest_01、tdc_memory_06_full、device_residue_02 及 复测_* 目录（2026-09-18 复测）
├── 海光Guest/
│   ├── results/        env_facts / e2e_result / bench_result / forensics_report / channel_capture.bin / guest_service.log
│   └── 脚本/           guest_infer_server.py、host_client.py、bench_e2e.py、host_forensics.py、run_guest.sh
└── 原始报告/           TDC模块2_密态推理验证报告.htm、TDC安全证明报告.htm、security_matrix.htm
```

鲲鹏平台的实验脚本与 FEC 共用，统一放在 [`../03_FEC_全密态计算/证据/实验代码/scripts/`](../03_FEC_全密态计算/证据/实验代码/scripts/)。
