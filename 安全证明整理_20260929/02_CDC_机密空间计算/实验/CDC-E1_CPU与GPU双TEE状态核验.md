# CDC-E1 CPU 与 GPU 双 TEE 状态核验

| 项目 | 内容 |
| --- | --- |
| 对应条目 | CDC-01 GPU-CC 正式模式确认、CDC-02 CPU-TEE 可信状态（状态部分） |
| 地点 | B200 服务器：宿主 gpuhost 与 TDX 机密虚机 tdx-cvm |
| 时间 | 2026-09-23 ~ 09-24 |
| 结果 | 通过：CVM 内 CPU（TDX）与 GPU（CC）同时处于机密计算状态 |

## 目的

证明同一台物理机上，CVM 内的 CPU 和 GPU 都处于正式的机密计算模式，而不是开发、调试或非机密模式。

## 方法

**同一时刻两侧对照**：在 CVM 内和宿主上分别查询 GPU 机密计算状态，再从 CVM 启动日志核对 TDX 是否激活。

## 过程

1. 宿主启用 TDX（BIOS 已开，`virt/tdx: BIOS enabled: private KeyID range [32, 64)`），libvirt 能力含 `<launchSecurity>tdx</launchSecurity>`。
2. 把 1 张 B200 从 nvidia 驱动解绑，改绑 vfio-pci，挂到 pcie-root-port 下透传给 CVM。
3. 用 QEMU `tdx-guest` 对象 + `OVMF.inteltdx` 启动 Ubuntu 24.04 CVM，串口日志全量保存。
4. 在 CVM 内和宿主上分别运行 `nvidia-smi conf-compute` 查询，结果保存为 `cvm_evidence.txt`、`host_evidence.txt`。

## 结果

| 字段 | CVM 内（持有透传 GPU） | 宿主上 |
| --- | --- | --- |
| CC State | **ON** | OFF |
| CPU CC Capabilities | **INTEL TDX** | None |
| CC GPUs Ready State | **Ready** | Not Ready |
| CC Environment | **PRODUCTION** | — |
| Protected memory | **185,970,368 KiB（约 177 GB）** | 原始文件未采集 |
| Unprotected memory | **0 KiB** | 原始文件未采集 |
| 透传卡驱动绑定 | — | `18:00.0 … [B200] Kernel driver in use: vfio-pci` |

宿主环境：内核 7.0.0-31-generic，启动参数含 `kvm_intel.tdx=1 intel_iommu=on`；QEMU 10.2.1；`virt/tdx: module initialized`，PAMT 7,879,732 KB。

CVM 启动日志：

```
[    0.000000] tdx: Guest detected
[    4.360973] Memory Encryption Features active: Intel TDX
```

宿主 `nvidia-smi` 只剩 7 张卡，透传的那张已从宿主驱动层消失。

## 证据文件

- `../证据/B200_TDX_CC/cvm_evidence.txt`、`host_evidence.txt`
- `../证据/B200_TDX_CC/cvm-console.log`

## 说明

- 本次为单卡透传；多卡 CC 域（Multi-GPU Mode）与 NVLink 未测。
- 宿主重启后需重新做 vfio 绑定、调大 `dma_entry_limit`（重启后回落为 65535），并复查 CC 模式。
