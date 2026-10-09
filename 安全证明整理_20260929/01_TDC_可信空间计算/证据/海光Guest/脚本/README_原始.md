# TDC 模块 2 —— 海光平台 Guest 内密态大模型推理

验证日期 2026-09-23　宿主 m01r4n12（Hygon C86 / 128 核 / 503 GB）　模型 Qwen2.5-0.5B-Instruct

完整图文报告见 **[TDC模块2_密态推理验证报告.htm](TDC模块2_密态推理验证报告.htm)**（含架构图、性能图、安全任务汇总表）。
本文件是配套的技术说明，供直接改代码和复现的人使用。

---

## 一、结论先说

**已达成**：完整大模型推理真正跑在独立的 Guest 虚拟机内部，并打通端到端密态链路
（客户端加密 → 信道只走密文 → Guest 内解密 → Guest 内推理 → 加密回传 → 客户端解密）。
宿主在信道上抓不到任何明文，加解密开销只占端到端时延的 0.0021%。

**未达成**：海光 CSV 内存加密没有启用，所以拥有 root 的宿主管理员**仍然能从 QEMU 进程内存里捞到明文 prompt**
（实测命中）。根因不是代码，是宿主内核缺一个启动参数，需要重启才能加上。

**对外表述的边界**：可以说「信道上宿主只见密文，会话私钥不出 Guest」；
不能说「宿主无法获取明文」或「宿主看不到模型」。

---

## 二、关键数据

运行规模

- Guest 冷启动到服务就绪：25 秒
- Guest 内模型加载：1.0 秒（954 MB 权重，290 个张量，mmap）
- Guest 配置：8 vCPU / 8 GB / 独立内核 6.6.0-euler / 独立 ext4 根盘

性能（6 个梯度爬坡用例，每条 query 内容唯一以排除缓存命中）

- S1 短：输入 51 → 输出 48 token，端到端 6.65 s，TPOT 138.5 ms
- S2 短：输入 52 → 输出 64 token，端到端 8.79 s，TPOT 137.4 ms
- M1 中：输入 67 → 输出 64 token，端到端 8.93 s，TPOT 139.6 ms
- M2 中：输入 78 → 输出 64 token，端到端 9.01 s，TPOT 140.8 ms
- L1 长：输入 99 → 输出 64 token，端到端 11.34 s，TPOT 177.2 ms
- L2 长：输入 100 → 输出 64 token，端到端 11.69 s，TPOT 182.7 ms
- 平均：端到端 9.41 s，TPOT 152.7 ms

加密代价

- 单次加解密总开销 0.15–0.25 ms，平均 0.185 ms
- 占端到端时延 0.0021%
- 该开销只与消息长度有关，与模型规模无关，换大模型后占比只会更低

---

## 三、安全任务验证结果

通过的项

- A1 数据方到 TEE 的传输加密 —— AES-256-GCM，1039 字节抓包中明文关键词 0 命中
- A2 明文只在 Guest 内出现 —— Guest 日志 `decrypted request (17 chars) in-guest`，宿主同期只有密文
- A3 推理结果加密后才离开 TEE —— 响应体仅含 nonce 与密文
- A4 会话密钥协商、私钥不外泄 —— X25519 私钥在 Guest 内生成，信道上只出现公钥
- A5 防缓存命中的评测方法 —— 每条 query 追加唯一编号，输入 51→100 token 递增
- A6 完整模型在 Guest 内推理 —— 非宿主代跑，Guest 有独立内核、rootfs、Python 栈
- A7 Guest 与宿主的执行隔离 —— Guest 无网络设备，对外仅一条 virtio-serial 信道

暴露的项（如实记录，不做美化）

- A8 宿主内存中的明文 —— root 扫描 QEMU 进程 9.5 GB 地址空间，**明文 prompt 命中 2 次**
- A9 磁盘镜像中的模型 —— 24 GB 裸镜像中命中 `Qwen2ForCausalLM`，权重可被宿主直接提取

受阻与未开展

- A10 CSV 内存加密启用 —— 硬件与内核就绪，缺宿主内核启动参数，见第五节
- A11 远程证明 —— 依赖 A10，CSV 未启用时没有可信度量报告可签发
- A12 模型权重密态存储 —— 需配合 A10，做完可消除 A9

---

## 四、代码与接口

### 文件职责

- `guest_infer_server.py`（Guest 内）：生成 X25519 密钥对、解密请求、调用 Qwen 推理、加密响应
- `host_client.py`（宿主）：协商会话密钥、加密 prompt、解密结果，并把信道原始字节落盘取证
- `bench_e2e.py`（宿主）：梯度爬坡评测，统计 TPOT、端到端时延、加解密开销
- `host_forensics.py`（宿主，需 root）：四项安全取证
- `run_guest.sh`（宿主）：以普通用户启动 Guest，挂 virtio 根盘与 virtio-serial 信道
- `results/`：本次验证的全部原始产物

### 通信协议（NDJSON，一行一个 JSON 对象）

握手

```
客户端 → Guest   {"type":"hello"}
Guest → 客户端   {"type":"pubkey","pub":"<base64 X25519 公钥>","model":"<名称>"}
```

推理

```
客户端 → Guest   {"type":"req",
                  "epk":"<base64 客户端临时公钥>",
                  "nonce":"<base64 12 字节>",
                  "ct":"<base64 AES-256-GCM 密文>"}
Guest → 客户端   {"type":"resp",
                  "nonce":"<base64>",
                  "ct":"<base64>",
                  "stats":{"prompt_tokens":38,"gen_tokens":62,"latency_s":8.97}}
```

保活

```
客户端 → Guest   {"type":"ping"}   →   {"type":"pong"}
```

密钥派生：双方各自用 X25519 做 ECDH 得共享密钥，再经
`HKDF-SHA256(info="tdc-module2-session-v1")` 派生 32 字节 AES-256-GCM 密钥。
Guest 私钥在进程启动时生成于内存，不落盘、不传输。

**接入尤旺团队标准 prompt 接口时**：只需在客户端一侧做协议转换，Guest 内服务无需改动。

### 服务器目录

```
/home/songyihong/tdc_module2/
├── guest_rootfs.img          Guest 根盘（24 GB raw，ext4，LABEL=tdcroot）
├── vmlinuz-6.6.0-euler       Guest 内核
├── initramfs-guest.img       通用 initramfs（含 virtio 驱动）
├── model_clean/              校验通过的原始权重
├── run_guest.sh / host_client.py / bench_e2e.py / host_forensics.py
├── tdc.chan0.sock            virtio-serial 信道（运行时存在）
├── guest-console.log         Guest 串口全量日志
└── channel_capture.bin / e2e_result.json / bench_result.json / forensics_report.json

Guest 镜像内部：
/opt/tdc/guest_infer_server.py           推理服务
/opt/tdc/model/                          模型权重（954 MB）
/etc/systemd/system/tdc-infer.service    开机自启
```

### 复现

```bash
# 1. 启动 Guest（约 25 秒服务就绪）
bash /home/songyihong/tdc_module2/run_guest.sh
grep '\[guest\]' /home/songyihong/tdc_module2/guest-console.log

# 2. 单次端到端密态推理
python3 host_client.py --sock tdc.chan0.sock --prompt "你的问题" \
        --capture channel_capture.bin --json-out e2e_result.json

# 3. 梯度爬坡评测
python3 bench_e2e.py --sock tdc.chan0.sock --out bench_result.json

# 4. 安全取证（内存扫描需 root）
sudo python3 host_forensics.py --dir . --result-json e2e_result.json \
        --out forensics_report.json --max-scan-gb 12
```

---

## 五、CSV 受阻的确切原因与修复

### 已具备的条件

- CPU 支持：`/proc/cpuinfo` 含 `csv` 标志，CPUID 0x8000001F 显示 SME=1 SEV=1 SEV-ES=1
- C-bit 参数：CBITPOS=47，物理地址位缩减=**3**（注意不是常见的 5，不能照抄 AMD EPYC 经验值）
- PSP 在线：`ccp 0000:12:00.4: CSV API:1.5 build:2446`，平台状态 INIT
- 内核支持：`kvm_amd: CSV enabled (ASIDs 1-500)`、`CSV2 enabled`、`CSV3 enabled`
- QEMU 支持：升级到 8.2.0-56 后二进制含 `csv3_init`、`csv3_launch_encrypt_data` 等完整海光 CSV3 符号
- 固件：edk2-ovmf-202308-32，含 `ovmf.amdsev/OVMF.fd`

### 缺的那一项

`/sys/kernel/mm/csv3_cma/mem_info` 显示 **total cma size: 0 MiB**。

开机第 0.02 秒的内核日志已经说明一切：

```
[ 0.021738] CSV: Fail, either kernel param csv_mem_percentage or
            csv_smcr_size&csv_use_hugetlb is required
[ 0.021739] CSV: Don't reserve any memory
[ 3.412253] ccp 0000:12:00.4: CSV3: fail to set secure memory region,
            CSV3 support unavailable
```

当前内核命令行里没有任何 csv 参数：

```
BOOT_IMAGE=/vmlinuz-6.6.0-euler root=/dev/mapper/openeuler-root ro
rd.lvm.lv=openeuler/root cgroup_disable=files apparmor=0 crashkernel=512M rhgb quiet
```

CSV3 需要在启动阶段预留一块连续安全内存（CMA），运行时无法补救。没有预留，PSP 拒绝建立加密上下文，
表现为 QEMU 侧：

```
qemu-kvm: sev_launch_start: LAUNCH_START ret=1 fw_error=21 'Feature not supported'
qemu-kvm: sev_kvm_init: failed to create encryption context
```

**已排除是调用方式问题**：穷举 8 组参数组合（policy 取 0x0/0x1/0x20/0x21，带与不带 `user-id`）
外加 q35 与 pc 两种机型，错误码完全一致；libvirt 能力查询也返回 `<sev supported='no'/>`。

### 修复步骤（本次未执行，按用户决定保持机器状态不变）

1. 备份 `/etc/default/grub`
2. 在 `GRUB_CMDLINE_LINUX` 追加 `csv_mem_percentage=50`
3. `grub2-mkconfig -o /boot/grub2/grub.cfg`，建议用一次性启动项便于失败回退
4. 重启后确认 `csv3_cma/mem_info` 的 total cma size 不再是 0，dmesg 不再报 `CSV3 support unavailable`
5. 以 `-object sev-guest,id=sev0,cbitpos=47,reduced-phys-bits=3,policy=0x1` 重试
6. 重跑取证，**预期 A8 由「暴露」转为「未命中」**，安全闭环完整

---

## 六、踩过的坑（复现时可直接跳过）

**宿主「没有外网」是误判**。IP 层完全通（ping 223.5.5.5 往返 15 ms），
只是 `/etc/resolv.conf` 是指向 `/run/systemd/resolve/` 的悬空符号链接，而 systemd-resolved 未启用。
删掉悬空链接、写入常规 nameserver 后，openEuler 源、PyPI、hf-mirror 全部恢复。
此前「只能从本地上传大文件」的整条路线都是被这个假象带偏的。

**PyTorch 别从本地传**。Windows 版含 `c10.dll` 不能用；PyPI 默认 `torch==2.5.1` 是 CUDA 版，
缺 `libcudart.so.12`。DNS 修好后在目标 rootfs 内直接
`pip install --index-url https://download.pytorch.org/whl/cpu torch` 一步到位。

**模型文件要校验**。宿主上原有的 model.safetensors 是 1,645,238,848 字节的损坏文件
（正确 988,097,824 字节），表现为 `SafetensorError: incomplete metadata`。
校验方法：读前 8 字节得头长 N，解析 N 字节 JSON 头，取所有张量 `data_offsets[1]` 的最大值，
验证 `8 + N + max_offset == 文件大小`。

**initramfs 要用 generic 模式**。宿主的 initramfs 是 hostonly 的，只含宿主 LVM 驱动，引导不了 virtio 根盘。
用 `dracut --no-hostonly --add-drivers "virtio_blk virtio_pci virtio_console ext4"` 重新生成。

**QEMU 以普通用户跑**（用户需在 kvm 组）。这样 unix socket 属主正确，客户端才连得上。
但 dracut 生成的 initramfs 是 0600 root，需要 chmod 644 否则 QEMU 读不到。

**`reduced-phys-bits` 是必填参数**，尽管 `-object sev-guest,help` 没把它列出来。
本机正确值是 3，必须从 CPUID 0x8000001F 的 EBX[11:6] 读，别照抄别人的 5。

**`sudo -S` 不能和 heredoc 或管道传数据共用 stdin**，否则密码会被当成数据写进目标文件
（本次就把密码写进过 `/etc/resolv.conf`，已覆盖）。需要写入内容的提权操作，
一律先写临时文件再 `sudo cp`。

---

## 七、后续建议

1. **优先级最高**：安排宿主重启窗口启用 CSV3。这是把 A8、A9 从「暴露」转为「受保护」的唯一途径，
   也是整个密态方案价值的支点。
2. CSV3 启用后补做远程证明（A11），让数据方在交付密钥前能验证对端确实是预期的 Guest 镜像。
3. 模型权重改密态存储（A12），消除宿主直接提取权重的风险。
4. 当前 initramfs 904 MB（dracut 全驱动），可裁剪到几十 MB，缩短启动并减少攻击面。
5. 评测脚本已按「唯一 query + 梯度爬坡」设计，换机型可直接复用，保证横向可比。
