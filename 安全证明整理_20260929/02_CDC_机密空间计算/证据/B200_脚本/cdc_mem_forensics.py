#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CDC 安全验证 —— 宿主内存取证（带正控制）

以"拥有 root 的宿主管理员"视角，尝试从 TDX 机密虚拟机的 QEMU 进程
地址空间里捞出 Guest 内的明文。

实验设计（关键在正控制，否则"没找到"没有意义）：
  正控制 PC：宿主上另起一个普通进程，持有同一个标记串。
             扫描器必须能在它里面找到标记，才证明扫描方法有效。
  被测目标 T：运行 TDX CVM 的 QEMU 进程。
             CVM 内有一个进程持有同一个标记串。

判读：
  PC 命中 + T 未命中  -> TDX 内存加密生效，宿主读不到 Guest 明文
  PC 命中 + T 命中    -> 内存未受保护（等同于海光 TDC 那侧的结果）
  PC 未命中           -> 扫描方法无效，本次实验作废，不得下任何结论
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time


def sh(c):
    return subprocess.run(c, shell=True, capture_output=True, text=True).stdout


def scan_pid(pid, needles, max_bytes=None, label=""):
    """扫描指定进程的可读内存段，返回每个标记的命中次数。"""
    res = {"pid": pid, "label": label, "scanned_mb": 0.0,
           "hits": {}, "regions": 0, "error": None}
    maps_path = "/proc/%d/maps" % pid
    mem_path = "/proc/%d/mem" % pid
    if not os.path.exists(maps_path):
        res["error"] = "process gone"
        return res
    if not os.access(mem_path, os.R_OK):
        res["error"] = "no read access (need root)"
        return res

    nb = [n.encode() for n in needles]
    scanned = 0
    try:
        fm = open(mem_path, "rb", 0)
    except Exception as e:
        res["error"] = str(e)
        return res

    with fm:
        try:
            lines = open(maps_path).readlines()
        except Exception as e:
            res["error"] = str(e)
            return res
        for line in lines:
            parts = line.split()
            if len(parts) < 2 or "r" not in parts[1]:
                continue
            # 跳过映射到文件的只读段以外的特殊区域
            try:
                lo, hi = [int(x, 16) for x in parts[0].split("-")]
            except Exception:
                continue
            size = hi - lo
            if size <= 0 or size > 64 * 1024 ** 3:
                continue
            res["regions"] += 1
            try:
                fm.seek(lo)
            except Exception:
                continue
            remaining = size
            tail = b""
            while remaining > 0:
                chunk = min(remaining, 32 * 1024 * 1024)
                try:
                    buf = fm.read(chunk)
                except Exception:
                    break
                if not buf:
                    break
                scanned += len(buf)
                hay = tail + buf
                for n in nb:
                    c = hay.count(n)
                    if c:
                        k = n.decode()
                        res["hits"][k] = res["hits"].get(k, 0) + c
                tail = hay[-256:]
                remaining -= len(buf)
                if max_bytes and scanned > max_bytes:
                    break
            if max_bytes and scanned > max_bytes:
                break
    res["scanned_mb"] = round(scanned / 1024 ** 2, 1)
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--canary", required=True, help="要搜索的明文标记")
    ap.add_argument("--target-pattern", default="tdguest.qcow2",
                    help="被测 QEMU 进程的命令行特征")
    ap.add_argument("--control-pattern", default="CDC_POSITIVE_CONTROL",
                    help="正控制进程的命令行特征")
    ap.add_argument("--max-scan-gb", type=float, default=20)
    ap.add_argument("--guest-selfscan-hits", type=int, default=None,
                    help="Guest 内自扫命中次数，用于确认实验有效")
    ap.add_argument("--out", default="/tmp/cdc_mem_forensics.json")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("WARNING: not root, /proc/*/mem 不可读", file=sys.stderr)

    needles = [args.canary]
    max_bytes = int(args.max_scan_gb * 1024 ** 3)

    def find_pid(pattern, comm_prefix):
        """按命令行特征找进程，并用 /proc/<pid>/comm 过滤进程类型。

        必须过滤：执行本实验的 shell 脚本命令行里同时含有标记串和目标特征，
        会被两个 pgrep 同时命中，污染判读。
        """
        out = sh("pgrep -f '%s'" % pattern).split()
        me = str(os.getpid())
        ppid = str(os.getppid())
        picked = []
        for p in out:
            if p in (me, ppid):
                continue
            try:
                comm = open("/proc/%s/comm" % p).read().strip()
            except Exception:
                continue
            if not comm.startswith(comm_prefix):
                continue
            picked.append(int(p))
        return picked

    ctrl_pids = find_pid(args.control_pattern, "python")
    tgt_pids = find_pid(args.target_pattern, "qemu")

    def pinfo(p):
        try:
            comm = open("/proc/%d/comm" % p).read().strip()
        except Exception:
            comm = "?"
        return {"pid": p, "comm": comm}

    report = {
        "canary": args.canary,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "control_pids": [pinfo(p) for p in ctrl_pids],
        "target_pids": [pinfo(p) for p in tgt_pids],
        "running_as_root": os.geteuid() == 0,
        "guest_selfscan_hits": args.guest_selfscan_hits,
    }

    # 实验有效性前置条件：Guest 内必须确实驻留该明文
    if args.guest_selfscan_hits is not None and args.guest_selfscan_hits <= 0:
        report["verdict"] = "INVALID"
        report["detail"] = ("Guest 内自扫未命中，说明标记并未真实驻留于 Guest 内存，"
                            "本次实验不得出任何结论")
        print("[!] Guest 自扫命中 0 次，实验作废")
        with open(args.out, "w") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        return 2

    # --- 正控制 ---
    print("[1] 正控制：扫描宿主普通进程（必须命中，否则实验作废）")
    ctrl_res = []
    for p in ctrl_pids[:2]:
        r = scan_pid(p, needles, max_bytes=2 * 1024 ** 3, label="positive_control")
        ctrl_res.append(r)
        print("    pid=%d scanned=%.1fMB hits=%s err=%s"
              % (p, r["scanned_mb"], r["hits"], r["error"]))
    report["control"] = ctrl_res
    control_ok = any(r["hits"] for r in ctrl_res)
    print("    => 正控制 %s" % ("命中，扫描方法有效" if control_ok else "未命中，方法无效"))

    # --- 被测目标 ---
    print("\n[2] 被测目标：扫描 TDX CVM 的 QEMU 进程")
    tgt_res = []
    for p in tgt_pids[:2]:
        r = scan_pid(p, needles, max_bytes=max_bytes, label="tdx_qemu")
        tgt_res.append(r)
        print("    pid=%d scanned=%.1fMB regions=%d hits=%s err=%s"
              % (p, r["scanned_mb"], r["regions"], r["hits"], r["error"]))
    report["target"] = tgt_res
    target_hit = any(r["hits"] for r in tgt_res)

    # --- 判读 ---
    if not control_ok:
        verdict = "INVALID"
        detail = "正控制未命中，扫描方法无效，本次实验不得出任何结论"
    elif target_hit:
        verdict = "EXPOSED"
        detail = "宿主可从 QEMU 进程内存读到 Guest 明文，内存未受保护"
    else:
        verdict = "PROTECTED"
        detail = ("正控制命中而被测目标未命中：在扫描覆盖范围内，"
                  "宿主无法从 QEMU 进程内存读到 Guest 明文")
    report["verdict"] = verdict
    report["detail"] = detail

    print("\n[3] 判读：%s" % verdict)
    print("    %s" % detail)

    with open(args.out, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print("\nwrote %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
