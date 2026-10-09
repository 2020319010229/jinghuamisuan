# TDC-E1 机密虚机状态与远程证明负例

| 项目 | 内容 |
| --- | --- |
| 对应条目 | TDC-01 架构与可信边界、TDC-02 CPU-TEE 可信状态与远程证明、G-02 环境基线 |
| 地点 | 鲲鹏 920 宿主机 + virtCCA 机密虚机（CVM 地址 192.168.122.143） |
| 时间 | 首轮 2026-09-16，复测 2026-09-18 |
| 结果 | 通过：证明负例 7/7（首轮与复测一致） |

## 目的

确认业务实际运行在已启用的 CPU 机密虚机中，且远程证明校验会拒绝伪造、篡改或不匹配的证明材料。

## 方法

1. **状态核查（只读）**：读取宿主上 qemu 进程命令行、设备绑定、固件与驱动版本，形成环境基线。
2. **证明负例**：采集一份真实的 CVM 证明 token，按当前 SDK 策略和严格 COSE 策略分别校验，再逐项构造异常输入，观察是否被拒绝。

## 过程

| 步骤 | 操作 | 脚本 |
| --- | --- | --- |
| 1 | 读取 qemu 命令行、vfio 绑定、IOMMU 分组 | `security_environment_baseline.py` |
| 2 | 查询两卡固件与宿主 / CVM 驱动版本 | `security_firmware_query.py` |
| 3 | 以新鲜 challenge 获取证明 token，离线执行 7 项校验 | `security_attestation_controls.py`、`security_run_attestation_controls.py` |

## 结果

**环境状态**

| 项 | 观测值 |
| --- | --- |
| TEE 模式 | qemu 参数 `kvm-type=cvm` + `tmm-guest`，`dump-guest-core=off` |
| 加速卡 | 2 × Ascend 310P3，均为 vfio-pci 直通 |
| 固件 / 驱动 | 两卡固件 7.8.0.7.220；宿主驱动 25.5.2，CVM 驱动 25.2.0 |
| 运行二进制 | 运行进程 `/proc/<pid>/exe` 摘要与部署二进制一致（`e015292c…`） |

**证明负例（7/7）**

| 用例 | 结果 |
| --- | --- |
| 采集的 token 按当前策略校验 | 通过 |
| 采集的 token 按严格 COSE 策略校验 | 通过 |
| 错误的新鲜 challenge | 拒绝 |
| 错误的度量值 | 拒绝 |
| 篡改 CVM COSE 签名最后一字节（偏移 1424），当前策略 | 拒绝 |
| 同上，严格 COSE 策略 | 拒绝 |
| 缺少设备证书 | 拒绝 |

## 证据文件

- `../证据/鲲鹏virtCCA/attest_01/controls.json`（首轮）
- `../证据/鲲鹏virtCCA/复测_attest/controls.json`（复测）
- `../证据/鲲鹏virtCCA/复测_env/env_baseline.json`、`复测_firmware/firmware.json`、`复测_live/live_status.json`

## 说明

- 本实验验证的是**校验逻辑能否拒绝异常输入**。可信根证书与第三方批准的度量基线尚未取得，度量值目前是观测值。
- SDK 当前配置 `KUNPENG_REQUIRE_COSE=0`、`measurement_reference_configured=false`；正式交付前建议把严格 COSE 和度量基线设为默认。
