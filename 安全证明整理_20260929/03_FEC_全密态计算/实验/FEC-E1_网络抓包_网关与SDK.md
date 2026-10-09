# FEC-E1 网络抓包（网关与 SDK）

| 项目 | 内容 |
| --- | --- |
| 对应条目 | G-04 网络传输安全证明、FEC-04 网络传输密态验证、TDC-06（网络侧） |
| 地点 | 鲲鹏宿主（客户端 192.168.122.1）↔ CVM（192.168.122.143），宿主侧与 CVM 侧两点同时抓包 |
| 时间 | 2026-09-18（复测） |
| 结果 | 通过：网关 :8000 23/23，SDK :8101 11/11 |

## 目的

确认客户端到 CVM 的网络链路上看不到业务明文，并确认抓包方法本身有效。

## 方法

1. 每次运行生成唯一的合成标记，一个放进 prompt（**被测**），一个放进明文 HTTP 头（**阳性对照**）。
2. 在宿主和 CVM 两处同时抓取该连接的 TCP 流。
3. 重组 HTTP 流后检索：prompt 标记必须看不到，头部标记必须看得到；两处抓到的流必须逐字节一致。
4. 网关入口同时发送正常请求、重放请求、篡改请求，核对服务端响应与客户端所见一致。

脚本：`security_run_wire_probe.py`、`security_wire_probe.py`、`security_analyze_wire.py`、`security_sdk_probe.py`

## 结果

**网关 :8000（23 项）**

| 检查（宿主侧 / CVM 侧各一套） | 结果 |
| --- | --- |
| 方向流完整、无缺口或冲突重传 | 通过 |
| 阳性对照头部标记可见 | 通过 |
| **prompt 合成标记不可见** | 通过 |
| HTTP 边界完整 | 通过 |
| 健康检查 / 公钥 / 正常 / 重放 / 篡改 / 事后健康检查的响应与客户端一致 | 通过 |
| 宿主与 CVM 两处重组流完全一致 | 通过 |

抓包：宿主侧 129 个包、CVM 侧 67 个包，丢包均为 0；原始 pcap 为 `host.pcap`、`cvm.pcap`。

**SDK :8101（11 项）**：方向流、无缺口、对照头部可见、**prompt 标记不可见**、HTTP 边界、两处流一致，全部通过。宿主侧 92 个包、CVM 侧 46 个包，丢包均为 0。

## 证据文件

- `../证据/鲲鹏310P_复测/wire_gw/`（host.pcap、cvm.pcap、analysis.json、capture_result.json、client_result.json、orchestration.json）
- `../证据/鲲鹏310P_复测/wire_sdk/`（host.pcap、cvm.pcap、analysis.json、capture_result.json、sdk_result.json、orchestration.json）

## 说明

- 抓包证明的是“这条链路上看不到明文标记”，不等于加密算法本身被证明。
- 网关 :8000 的公钥经 HTTP 获取，没有与远程证明绑定（`identity_limit` 字段）；SDK :8101 带新鲜 challenge 的远程证明。
