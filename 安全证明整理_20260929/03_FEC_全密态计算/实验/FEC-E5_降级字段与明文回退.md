# FEC-E5 降级字段与明文回退

| 项目 | 内容 |
| --- | --- |
| 对应条目 | FEC-07 线性与非线性计算边界（无明文旁路或回退） |
| 地点 | 鲲鹏 virtCCA CVM，OTP 引擎 |
| 时间 | 首轮 2026-09-16（no_fallback_01），复测 2026-09-18 |
| 结果 | 通过：7 种降级字段全部无效 |

## 目的

确认请求方无法通过在请求中加字段，让引擎关闭 OTP 掩码、改走明文计算。

## 方法

1. 先发一次普通请求，记录基线输出 token 和引擎模式。
2. 依次在请求中加入 7 种可能的降级字段，每次比较输出 token 是否与基线相同、引擎模式是否变化。
3. 静态检查源码：掩码开关 `g_blind` 与 `g_r_scale` 的所有赋值点。

脚本：`security_fec_no_fallback.py`

## 结果

| 注入字段 | 输出与基线相同 | 引擎模式 |
| --- | --- | --- |
| `blind: 0` | 是 | shannon_rns_otp |
| `plain: true` | 是 | shannon_rns_otp |
| `mode: "plain"` | 是 | shannon_rns_otp |
| `otp: false` | 是 | shannon_rns_otp |
| `disable_otp: true` | 是 | shannon_rns_otp |
| `r_scale: 0` | 是 | shannon_rns_otp |
| `blind_mode: "plain"` | 是 | shannon_rns_otp |

- 测试前后健康状态模式均为 `shannon_rns_otp`（`mode_stable=true`，`no_downgrade_accepted=true`）。
- 静态检查：`g_blind`、`g_r_scale` 共 11 处引用，只能由启动命令行设置，请求体没有解析路径。

## 证据文件

- `../证据/鲲鹏310P_复测/no_fallback/result.json`
