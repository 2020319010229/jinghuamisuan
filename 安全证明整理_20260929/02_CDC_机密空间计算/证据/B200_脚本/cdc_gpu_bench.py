#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CDC 机密计算 GPU 性能基准

同一型号 B200、同一驱动分支，唯一变量是机密计算（CC）是否开启：
  - CVM 内：GPU 处于 CC 模式，显存全部受保护，CPU-GPU 之间走加密弹跳缓冲
  - 宿主上：GPU 未开 CC，为常规直通

因此两侧数据可直接相减，得到 CC 的真实开销。

测三类指标：
  1. H2D / D2H 主机-设备传输带宽（CC 开启时要经加密弹跳缓冲，预期明显下降）
  2. 设备内矩阵乘算力（纯 GPU 内部计算，预期几乎无损）
  3. 设备内显存拷贝带宽（HBM 内部，预期无损）
"""
import json
import os
import sys
import time

import torch


def sync():
    torch.cuda.synchronize()


def bench_h2d_d2h(mb=256, iters=20):
    n = mb * 1024 * 1024 // 4
    host = torch.empty(n, dtype=torch.float32).pin_memory()
    dev = torch.empty(n, dtype=torch.float32, device="cuda")
    # warmup
    for _ in range(3):
        dev.copy_(host, non_blocking=True)
    sync()

    t0 = time.perf_counter()
    for _ in range(iters):
        dev.copy_(host, non_blocking=True)
    sync()
    h2d = mb / 1024 * iters / (time.perf_counter() - t0)

    t0 = time.perf_counter()
    for _ in range(iters):
        host.copy_(dev, non_blocking=True)
    sync()
    d2h = mb / 1024 * iters / (time.perf_counter() - t0)
    return {"payload_mb": mb, "iters": iters,
            "h2d_gb_s": round(h2d, 2), "d2h_gb_s": round(d2h, 2)}


def bench_matmul(n=8192, dtype=torch.bfloat16, iters=30):
    a = torch.randn(n, n, device="cuda", dtype=dtype)
    b = torch.randn(n, n, device="cuda", dtype=dtype)
    for _ in range(5):
        c = a @ b
    sync()
    t0 = time.perf_counter()
    for _ in range(iters):
        c = a @ b
    sync()
    dt = time.perf_counter() - t0
    flops = 2.0 * n ** 3 * iters
    return {"n": n, "dtype": str(dtype).replace("torch.", ""), "iters": iters,
            "tflops": round(flops / dt / 1e12, 2),
            "ms_per_matmul": round(dt / iters * 1000, 3)}


def bench_d2d(mb=512, iters=30):
    n = mb * 1024 * 1024 // 4
    src = torch.empty(n, dtype=torch.float32, device="cuda")
    dst = torch.empty(n, dtype=torch.float32, device="cuda")
    for _ in range(3):
        dst.copy_(src)
    sync()
    t0 = time.perf_counter()
    for _ in range(iters):
        dst.copy_(src)
    sync()
    dt = time.perf_counter() - t0
    # 读+写各一次
    return {"payload_mb": mb,
            "d2d_gb_s": round(mb / 1024 * iters * 2 / dt, 2)}


def main():
    tag = sys.argv[1] if len(sys.argv) > 1 else "unknown"
    out = sys.argv[2] if len(sys.argv) > 2 else "/tmp/gpu_bench.json"

    if not torch.cuda.is_available():
        print("CUDA NOT AVAILABLE")
        json.dump({"tag": tag, "error": "cuda unavailable"},
                  open(out, "w"), indent=2)
        return 1

    props = torch.cuda.get_device_properties(0)
    info = {
        "tag": tag,
        "torch": torch.__version__,
        "cuda": torch.version.cuda,
        "device": props.name,
        "total_mem_gb": round(props.total_memory / 1024 ** 3, 1),
        "sm_count": props.multi_processor_count,
        "capability": "%d.%d" % (props.major, props.minor),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    print("[bench:%s] %s  torch=%s cuda=%s  %.1fGB  SM=%d"
          % (tag, info["device"], info["torch"], info["cuda"],
             info["total_mem_gb"], info["sm_count"]))

    res = {"info": info}

    print("  -> H2D/D2H transfer ...")
    res["transfer"] = bench_h2d_d2h()
    print("     H2D %.2f GB/s   D2H %.2f GB/s"
          % (res["transfer"]["h2d_gb_s"], res["transfer"]["d2h_gb_s"]))

    print("  -> device-to-device copy ...")
    res["d2d"] = bench_d2d()
    print("     D2D %.2f GB/s" % res["d2d"]["d2d_gb_s"])

    print("  -> matmul bf16 8192^3 ...")
    res["matmul_bf16"] = bench_matmul()
    print("     %.2f TFLOPS  (%.3f ms/matmul)"
          % (res["matmul_bf16"]["tflops"], res["matmul_bf16"]["ms_per_matmul"]))

    print("  -> matmul fp16 8192^3 ...")
    res["matmul_fp16"] = bench_matmul(dtype=torch.float16)
    print("     %.2f TFLOPS" % res["matmul_fp16"]["tflops"])

    res["mem_after"] = {
        "allocated_gb": round(torch.cuda.memory_allocated() / 1024 ** 3, 2),
        "reserved_gb": round(torch.cuda.memory_reserved() / 1024 ** 3, 2),
    }

    with open(out, "w") as f:
        json.dump(res, f, indent=2)
    print("[bench:%s] wrote %s" % (tag, out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
