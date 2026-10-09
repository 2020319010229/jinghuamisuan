# FEC-E2 协议与密钥安全验收

| 项目 | 内容 |
| --- | --- |
| 对应条目 | FEC-02 OTP 密钥全生命周期、G-04 异常连接阻断 |
| 地点 | 鲲鹏 virtCCA CVM，目标 `http://127.0.0.1:8000` |
| 时间 | 首轮 2026-09-16（acceptance_01 为 16/17，修复后 acceptance_02 为 17/17），复测 2026-09-18 |
| 结果 | 17/17 通过；另记录 1 项发现 F01 |

## 目的

一次性检查密钥协商、加密封装、篡改与重放防护，以及 OTP 掩码随机性与清零。

## 方法

脚本 `run_security_acceptance_20260828.py` 在 CVM 内对服务发起 17 项黑盒 / 白盒测试。随机性测试调用引擎同一套 CSPRNG 与 RNS 采样代码，生成掩码后统计唯一性和分布，最后验证清零。

## 结果

| # | 测试 | 关键观测 | 结果 |
| --- | --- | --- | --- |
| S01 | 服务健康与密态模式 | mode=`shannon_rns_otp` | 通过 |
| S02 | 鲲鹏 / 双 Ascend 310P / TP2 运行身份 | Kunpeng virtCCA，aarch64，192 vCPU | 通过 |
| S03 | 密钥协商算法与公钥长度 | X25519 + HKDF-SHA256 + AES-256-GCM，公钥 32 字节 | 通过 |
| S04 | 测试窗口内服务公钥稳定 | 两次获取一致 | 通过 |
| S05 | 服务私钥文件权限 | `/data/otp_c35/.tee_x25519.key`，32 字节，权限 0600 | 通过 |
| S06 | 请求线上封装不含明文和推理字段 | 线上字段仅 ciphertext / client_public_key / nonce / version，明文 0 命中 | 通过 |
| S07 | **4096 次请求 nonce 与密文唯一** | 4096 / 4096 唯一 | 通过 |
| S08 | 本地 AES-GCM 篡改与错误 AAD | 位翻转、错误 AAD 均被拒 | 通过 |
| S09 | 在线密文篡改 | HTTP 400 | 通过 |
| S10 | 协议版本 / AAD 降级 | HTTP 400 | 通过 |
| S11 | 非法 nonce 长度 | HTTP 400 | 通过 |
| S12 | 非法 X25519 公钥长度 | HTTP 400 | 通过 |
| S13 | 端到端加密推理与响应认证解密 | HTTP 200；响应线上只有 ciphertext / nonce / version | 通过 |
| S14 | 同一 client 公钥 + nonce 重放 | HTTP 400 | 通过 |
| S15 | 未知路由默认拒绝 | HTTP 404 | 通过 |
| S16 | **CSPRNG 唯一性 / 均匀性 / 清零** | 见下方原始输出 | 通过 |
| S17 | RNS 掩码生成与清零代码路径 | getrandom、拒绝采样、安全清零 | 通过 |

S16 原始输出：

```
CSPRNG masks=4096 width=256 unique=4096 mean=0.00012061 variance=0.0833057 zeroize=PASS
RNS q=32749 samples=1048576 range=[0,32748] mean=16362.422 variance_ratio=0.999964
RNS q=32719 samples=1048576 range=[0,32718] mean=16356.486 variance_ratio=1.001224
RNS_MOD_UNIFORM_PASS rejection-sampled exact domains
```

## 发现 F01（HIGH，未整改）

网关在 `0.0.0.0` 监听的端口上，明文推理路由 `/v1/chat/completions` 仍然存在（请求返回 400 而不是 404）。实际公网可达性还需结合边界防火墙确认。建议：生产关闭该路由，或只监听 loopback / 可信管理网，并加 mTLS 或网络策略。

## 证据文件

- `../证据/鲲鹏310P_复测/acceptance/security_acceptance_raw.json`

## 说明

测试范围是接口、密码协议、CSPRNG/RNS 实现；未做 DoS、资源耗尽、微架构侧信道。
