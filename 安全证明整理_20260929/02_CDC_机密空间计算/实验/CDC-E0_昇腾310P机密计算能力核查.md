# CDC-E0 昇腾 310P 机密计算能力核查

| 项目 | 内容 |
| --- | --- |
| 对应条目 | CDC-01 平台组合核对（作为平台选择依据） |
| 地点 | 鲲鹏 virtCCA CVM 内，对 2 张 Ascend 310P3 只读查询 |
| 时间 | 2026-09-18 |
| 结果 | 平台不具备 GPU-CC 能力 → CDC 实验改在 B200 上进行 |

## 方法

在 CVM 内用 `npu-smi` 只读查询设备的安全相关能力，并检查驱动 / CANN 中是否有机密计算相关符号。脚本：`probe.sh`、`security_cdc_platform_check.py`。

## 结果

| 查询项 | 观测 |
| --- | --- |
| 型号 / 固件 | Atlas 300V Pro / Ascend 310P3，固件 7.8.0.7.220 |
| work-mode | 不支持查询 → 没有机密 / 非机密模式可确认 |
| rootkey、tls-cert | 不支持查询 → 没有设备身份材料，产不出设备级证明 |
| key-manage | auto startup: Disable，running status: Stop |
| 驱动 / CANN 符号 | 无 attest / confidential / cc_mode / secure_boot |

## 证据文件

- `../证据/昇腾310P_平台核查/cdc01_platform/npu_security_capability.txt`、`probe.sh`
- `../证据/昇腾310P_平台核查/复测_cdc/result.json`（`cdc_capable: false`）
