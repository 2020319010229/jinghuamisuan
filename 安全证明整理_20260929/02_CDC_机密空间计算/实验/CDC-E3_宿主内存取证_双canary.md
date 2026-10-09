# CDC-E3 宿主内存取证（双 canary）

| 项目 | 内容 |
| --- | --- |
| 对应条目 | CDC-05 CPU 内存隔离（宿主反向访问） |
| 地点 | B200 服务器宿主 gpuhost（root）→ TDX CVM 的 QEMU 进程（pid 280990） |
| 时间 | 2026-09-24 |
| 结果 | 通过：纯内存 canary 在 Guest 内驻留 24,102 份，宿主扫描 16,659.8 MB / 498 个区域 **0 命中** |

## 目的

模拟 root 宿主管理员，直接扫描机密虚机的 QEMU 进程内存，看能否取到 Guest 私有内存中的明文。

## 方法

三重保障，排除“标记没放进去”和“扫描方法无效”两种误判：

1. **Guest 自扫**：扫描前先在 Guest 内确认标记确实驻留；自扫 0 命中则实验作废。
2. **阳性对照**：宿主上另起一个持有相同标记的普通进程，扫描器必须能命中它。
3. **进程类型过滤**：按 `/proc/pid/comm` 限定目标必须是 qemu、对照必须是 python，排除执行脚本自身的 shell 干扰。

脚本：`cdc_mem_forensics.py`

## 过程与结果

**实验一：canary 经 SSH 命令行传入（2026-09-24 12:01）**

| 项 | 结果 |
| --- | --- |
| Guest 自扫 | 24,110 |
| 宿主阳性对照 | 24,108 |
| 宿主扫 QEMU 16,659.8 MB | **7** 次命中 → 初判 EXPOSED |

没有直接下结论，而是用定位器查命中位置：命中落在 QEMU 的 guest RAM 后端大映射中，内容是 `sudo` 审计日志行（`COMMAND=/usr/bin/python3 /tmp/selfscan.py CDC-CANARY-…`）。即测试命令经 journald 落盘，走 virtio-blk 的共享 DMA 缓冲留下的足迹。TDX 下 guest 私有页已从 QEMU 视图中移除，QEMU 仍能读到的是 guest 主动设为 shared 的设备 DMA 页。**泄漏渠道是 I/O 设备路径，不是私有内存保护失效。**

**实验二：纯内存 canary（定论实验，2026-09-24 12:05）**

canary 在 Guest 内用 `os.urandom` 生成，不进入命令行、不写盘（needle 放在 tmpfs `/dev/shm`），只打印 SHA-256 供对账。

| 项 | 结果 |
| --- | --- |
| 宿主阳性对照（pid 504853，20.6 MB） | 24,105 命中 → 扫描方法有效 |
| Guest 自扫（27.0 MB） | 24,102 命中 → 确实驻留 |
| 宿主扫 TDX CVM 的 QEMU 进程（16,659.8 MB，498 区域） | **0 命中** → PROTECTED |

## 证据文件

- `../证据/B200_TDX_CC/cdc_mem_forensics_v3.json`（实验一）
- `../证据/B200_TDX_CC/cdc_mem_forensics_pure.json`（实验二）
- `../证据/B200_TDX_CC/memtest_raw_logs.txt`（完整原始日志，含定位器 hex/ascii 输出）

## 说明

- 对外可以说：Guest 私有内存中的明文，宿主以 root 全量扫描 16.66 GB 读不到（0 命中，阳性对照 24,105 命中）。
- 不能说“宿主完全看不到任何数据”：经模拟设备（磁盘 / 网络）的数据宿主可见，需要传输层加密保护。
- 本实验覆盖 CPU 内存；GPU 显存侧的证据是 E1 中的保护状态（Protected 177 GB / Unprotected 0），未另做显存反向读取。
