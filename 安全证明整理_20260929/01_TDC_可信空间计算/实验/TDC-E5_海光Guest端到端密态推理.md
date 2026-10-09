# TDC-E5 海光 Guest 端到端密态推理

| 项目 | 内容 |
| --- | --- |
| 对应条目 | TDC-06 数据路径验证（传输与 Guest 内处理部分） |
| 地点 | 海光宿主 m01r4n12（Hygon C86 128 核 / 503 GB，openEuler 24.03 LTS-SP2） |
| 时间 | 2026-09-23 |
| 结果 | 通过：信道原始字节 1039 字节，明文关键词 0 命中；会话私钥不出 Guest |

## 目的

在独立 Guest 虚拟机内运行完整大模型推理，验证“客户端加密 → 信道只走密文 → Guest 内解密与推理 → 加密回传 → 客户端解密”整条链路。

## 环境

| 项 | 宿主 | Guest |
| --- | --- | --- |
| 虚拟化 | QEMU 8.2.0-56.oe2403sp2 + KVM，edk2-ovmf-202308-32 | q35，virtio-blk 根盘，直接内核引导 |
| 资源 | 128 核 / 503 GB | 8 vCPU / 8 GB，独立内核 6.6.0-euler、独立 rootfs |
| 推理栈 | — | torch 2.14.0+cpu，transformers 5.17.0 |
| 模型 | — | Qwen2.5-0.5B-Instruct（290 张量，988,097,824 字节） |
| 信道 | virtio-serial（`tdc.chan0.sock`），Guest 无网络设备 | |

## 方法

1. **密钥协商**：Guest 启动时在内存中生成 X25519 密钥对，私钥不落盘、不传输；客户端用临时密钥做 ECDH，经 HKDF-SHA256 派生 AES-256-GCM 会话密钥。
2. **端到端请求**：客户端加密 prompt 发送；Guest 解密、推理、加密回传；客户端解密。
3. **信道取证**：宿主把信道上的全部原始字节落盘，检索 prompt 和回答中的明文关键词。
4. **梯度评测**：6 个用例，输入 51→100 token 递增，每条 query 追加唯一编号，避免缓存命中。

## 过程

| 步骤 | 命令 / 脚本 |
| --- | --- |
| 启动 Guest（约 25 s 就绪） | `run_guest.sh` |
| 单次端到端请求并抓取信道 | `host_client.py --capture channel_capture.bin` |
| 梯度评测 | `bench_e2e.py` |
| 宿主取证 | `sudo host_forensics.py`（F1 信道、F4 密钥外泄） |

## 结果

**信道取证**

| 检查 | 结果 |
| --- | --- |
| F1 信道原始字节（1039 字节，2 段密文） | 明文关键词 0 命中 |
| F4 会话密钥外泄 | 信道上只有 Guest 公钥，无私钥和会话密钥 |
| Guest 日志 | `decrypted request (17 chars) in-guest`，解密与推理均在 Guest 内 |

**6 用例评测**

| 用例 | 输入 / 输出 token | Guest 推理 | 端到端时延 | 加解密开销 | TPOT |
| --- | --- | --- | --- | --- | --- |
| S1 | 51 / 48 | 6.649 s | 6.655 s | 0.241 ms | 138.5 ms |
| S2 | 52 / 64 | 8.793 s | 8.795 s | 0.175 ms | 137.4 ms |
| M1 | 67 / 64 | 8.932 s | 8.934 s | 0.152 ms | 139.6 ms |
| M2 | 78 / 64 | 9.008 s | 9.010 s | 0.208 ms | 140.8 ms |
| L1 | 99 / 64 | 11.338 s | 11.341 s | 0.172 ms | 177.2 ms |
| L2 | 100 / 64 | 11.693 s | 11.695 s | 0.161 ms | 182.7 ms |
| 平均 | 74.5 / 61.3 | | 9.405 s | 0.185 ms（占 0.0021%） | 152.7 ms |

## 证据文件

- `../证据/海光Guest/results/channel_capture.bin`、`e2e_result.json`、`bench_result.json`、`forensics_report.json`、`env_facts.json`、`guest_service.log`
- `../证据/海光Guest/脚本/`
- `../证据/原始报告/TDC模块2_密态推理验证报告.htm`

## 说明

本平台 CSV 内存加密未启用（宿主内核缺 `csv_mem_percentage` 启动参数，`LAUNCH_START fw_error=21`）。因此本实验只作为**传输与数据路径**证据；宿主内存侧的保护结论引用鲲鹏平台的 [TDC-E2](TDC-E2_宿主反向读取CVM内存.md)。
