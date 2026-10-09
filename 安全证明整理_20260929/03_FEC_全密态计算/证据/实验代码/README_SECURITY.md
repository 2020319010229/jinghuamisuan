# 安全实验代码说明（过程包用）

本目录是三类密态计算方案安全证明的全部实验代码。一条命令可重跑全部实验。

## 一、怎么跑

```bash
cd otp_c35

# 全量复测（约 60–90 分钟，内存全扫是长尾）
python scripts/security_rerun_all.py --output-dir results/security_recheck_YYYYMMDD

# 只跑某几项
python scripts/security_rerun_all.py --output-dir ... --only sdk,wire_gw,fault

# 跳过耗时项
python scripts/security_rerun_all.py --output-dir ... --skip memory

# 与首轮逐项对比
python scripts/security_compare_batches.py \
    --baseline results/security_full_20260918 \
    --recheck  results/security_recheck_YYYYMMDD \
    --output   results/security_recheck_YYYYMMDD/comparison.json

# 冻结证据并生成哈希清单
python scripts/security_finalize_batch.py \
    --directory results/security_recheck_YYYYMMDD \
    --batch recheck_YYYYMMDD --report <报告文件名>
```

前置条件：本机能连宿主机（VPN 通），`security_remote.py` 负责宿主与 CVM 两跳连接。

## 二、生产环境保护措施

实验跑在**在线的生产服务**上，编排器内置三条约束：

1. **碰设备的实验执行前检查后端是否空闲**（`active=0 且 queued=0`），非空闲则跳过而不是硬跑。涉及 `npu` / `workspace` / `dev_residue` / `fault` 四项。需要强行执行时加 `--allow-busy`。
2. **不在生产源码树内编译**。故障注入把引擎源码从 `/data/otp_c35` 拷到临时目录再编译。
3. **不用非法指针启动 kernel**。NPU 与线上服务共享，故障注入的非法参数用例都在触碰设备之前返回；设备权重篡改用例结束即还原并复验。

每项测试记录执行前后的后端 `requests` 与空闲状态，用于证明生产未受影响。

## 三、测试项与对应任务

| 项 | 说明 | 计划书任务 | 碰设备 |
| --- | --- | --- | --- |
| `env` | 环境与版本基线 | G-02 | |
| `firmware` | 两卡固件与驱动版本 | G-02 | |
| `live` | 线上健康与运行身份 | G-02 / TDC-06 | |
| `sdk` | SDK 客户端与重放控制 | G-03 / FEC-03 | |
| `attest` | 证明负例（伪造材料应被拒） | TDC-02 / FEC-01 | |
| `wire_gw` | 8000 网关入口双点抓包 | G-04 / FEC-04 | |
| `wire_sdk` | 8101 SDK 入口双点抓包 | G-04 / FEC-04 | |
| `pair` | 并发跨密钥隔离 | FEC-04 | |
| `dual_entry` | 明密文双入口输出一致 | FEC-06 | |
| `residue` | 旁路残留（日志/临时文件/容器日志） | FEC-05 | |
| `no_fallback` | 运行时不可降级为明文 | FEC-07 | |
| `cdc` | 加速卡机密计算能力核查 | CDC-01 / CDC-03 | |
| `tdc_access` | 非授权侧访问（宿主 + 非特权用户） | TDC-04 / TDC-07 | |
| `cancel` | 取消传播线上验收 | FEC-08 | |
| `npu` | NPU 设备接口合成算例 | FEC-05 | ✔ |
| `workspace` | workspace 生命周期 | FEC-02 | ✔ |
| `dev_residue` | 跨进程设备内存残留 | TDC-05 | ✔ |
| `fault` | 故障注入与安全回退 | FEC-08 | ✔ |
| `memory` | 宿主读 guest 内存全量扫描 | TDC-03 | |
| `selfcheck` | 客户自验（宿主以客户视角独立执行） | G-03 / 验收 | |
| `acceptance` | 加密入口篡改与重放 17 项 | FEC-04 | |

未列入的三项需要外部条件，脚本无法覆盖：物理 PCIe 总线观测（无仪器）、
跨租户越权（单租户环境）、纯明文引擎端到端基线对照（需停服务）。

## 四、脚本分类

**现役（复测链路在用）**——`security_rerun_all.py` 直接或间接调用：

- 编排与对比：`security_rerun_all.py`、`security_compare_batches.py`、`security_finalize_batch.py`
- 连接助手：`security_remote.py`（宿主与 CVM 两跳，全部脚本共用）
- 基线采集：`security_environment_baseline.py`、`security_firmware_query.py`、`security_live_status.py`
- 客户端与网络：`security_run_sdk_probe.py` + `security_sdk_probe.py`、
  `security_run_wire_probe.py` + `security_wire_probe.py`、`security_analyze_wire.py`、
  `security_run_sdk_pair.py` + `security_sdk_pair_probe.py`、`security_customer_selfcheck.py`
- 证明与验收：`security_run_attestation_controls.py` + `security_attestation_controls.py`、
  `run_security_acceptance_20260828.py`
- FEC 专项：`security_fec_dual_entry.py`、`security_fec_residue.py`、`security_fec_no_fallback.py`
- 设备侧：`security_run_npu_extended.py` + `security_npu_extended_probe.cpp`、
  `security_run_workspace_probe.py` + `security_workspace_probe.cpp`、
  `security_run_device_residue.py` + `security_device_memory_residue.cpp`
- 故障注入：`security_run_fault_injection.py` + `security_fault_injection.c` + `security_fault_getrandom.c`
- 隔离与平台：`security_tdc_memory_isolation.py`、`security_tdc_access_check.py`、
  `security_cdc_platform_check.py`
- 取消：`security_run_sdk_cancel.py` + `security_sdk_cancel_probe.py`

**历史/一次性工具**——上线、修复、旧版探针，保留以便追溯，不参与复测：
`security_release*.py`、`security_build_*.py`、`security_deploy_*.py`、
`security_finalize_deployment.py`、`security_finalize_fixes.py`、`security_verify_fixes.py`、
`security_freeze_followup.py`、`security_run_cancel_chain.py`、
`security_run_cancel_engine_tests.py`、`security_cancel_*.py`、
`security_snapshot_cancel_context.py`、`security_rng_boundary_test.c`、
`security_run_rng_boundary.py`、`security_npu_probe.cpp`、`security_run_npu_probe.py`（被
extended 版取代）、`security_restart_replay_probe.py`、`security_run_restart_replay.py`、
`security_replay_unit_controls.py`、`security_run_key_cleanup.py`、
`security_test_key_cleanup.py`、`security_model_inventory.py`、
`security_run_remaining_inventory.py`、`security_runtime_inspect.py`、
`security_run_runtime_inspect.py`、`security_connectivity_check.py`、
`security_crypto_local_check.py`、`security_sdk_nonstream_probe.py`、
`security_run_sdk_nonstream.py`

## 五、证据规范

- 每项写**独立输出目录**，绝不覆盖历史证据；`security_finalize_batch.py` 以 `x` 模式
  拒绝覆盖既有 manifest，重新冻结请用新批次号。
- 失败与作废记录**保留不删**，与成功记录并列。
- 阳性对照是硬要求：抓包、内存扫描、设备残留三项都配对照，
  **没有对照的"没搜到"视为无效证据**。
- 时间戳、run_id、nonce、临时目录名每轮必然不同，因此两轮比对用
  `security_compare_batches.py` 提取关键指标，而不是逐字节比整份 JSON。

## 六、已知的脚本级修正

2026-09-18 复测时修正了一处采集缺陷，记录于此以免后人踩坑：

`security_tdc_access_check.py` 的 npu-smi 段原先输出为空，曾被误读为"宿主未安装
npu-smi"。实际是宿主**装有** npu-smi（`/usr/local/sbin/npu-smi`），执行时挂起并被
`timeout` 杀掉（退出码 124），输出停在缓冲区里丢失。现改为先落盘再读，并显式记录
安装路径与退出码。**安全结论不变**——宿主依然访问不到设备，而且"工具在手也用不了"
比"没装"更有说服力。
