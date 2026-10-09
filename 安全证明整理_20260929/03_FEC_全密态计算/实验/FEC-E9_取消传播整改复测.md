# FEC-E9 取消传播整改复测

| 项目 | 内容 |
| --- | --- |
| 对应条目 | I-04 缺口整改与复测 |
| 地点 | 鲲鹏 virtCCA CVM 生产服务 |
| 时间 | 上线 2026-09-18（release security-20260918-01），复测同日 |
| 结果 | 通过：11/11 |

## 问题

客户端取消流式请求后，后端仍继续解码到结束。

## 整改

构建取消传播修复版引擎（候选二进制 SHA-256 `e015292c…09de0`），上线前记录引擎、网关及 cvm_server 各文件摘要，上线后核对运行进程摘要。

## 复测方法

1. 先跑一个参考流：32 个 delta，正常 done，解码批次 31 次。
2. 发起同样的流，在收到第 1 个 delta 后发送取消。
3. 观测：取消响应之后是否还有 delta、流如何结束、后端解码批次是否停止、服务是否空闲并恢复。

脚本：`security_run_cancel_chain.py`、`security_sdk_cancel_probe.py`

## 结果

| 指标 | 参考流 | 取消流 |
| --- | --- | --- |
| delta 事件 | 32 | 1 |
| 取消响应之后的 delta | — | 0 |
| 结束方式 | done | EOF（无 done） |
| 后端解码批次 | 31 | 1 |
| 后端取消已证实 | — | `backend_cancel_proven=true` |

11 项检查全部通过。上线首次运行（cancel_live_01）因脚本 RuntimeError 未完成，第二次（cancel_live_02）通过，复测（cancel）通过。

## 证据文件

- `../证据/鲲鹏310P_复测/cancel/cancel_result.json`、`orchestration.json`

## 说明

取消处理器不回传 worker 的中止结果；本实验不包括设备内存擦除，也不包括被取消 token 的精确计数。
