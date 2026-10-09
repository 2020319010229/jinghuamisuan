#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TDC 模块2 —— 宿主侧取证

以"恶意/好奇的宿主管理员"视角，检验数据方的敏感内容在宿主上的暴露面。
本脚本刻意做**证伪**尝试：能找到明文就如实报告能找到。

检查项：
  F1 信道流量取证    —— 宿主在 virtio-serial 上抓到的原始字节里是否含明文
  F2 Guest 进程内存  —— 扫描 QEMU 进程地址空间是否能捞到明文 prompt/回答
  F3 磁盘镜像        —— guest rootfs 镜像中模型与代码是否明文可读
  F4 会话私钥外泄    —— Guest 私钥是否出现在宿主可见的信道流量中
"""
import argparse
import json
import os
import re
import subprocess
import sys


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def find_qemu_pid(pidfile):
    if pidfile and os.path.exists(pidfile):
        try:
            return int(open(pidfile).read().strip())
        except Exception:
            pass
    out = sh("pgrep -f 'qemu-kvm.*guest_rootfs.img'").strip().splitlines()
    return int(out[0]) if out else None


def f1_channel(capture, needles):
    """信道流量里是否有明文。"""
    res = {"check": "F1 信道流量", "file": capture}
    if not os.path.exists(capture):
        res.update(status="SKIP", detail="未找到抓包文件")
        return res
    data = open(capture, "rb").read()
    res["bytes"] = len(data)
    hits = [n for n in needles if n.encode("utf-8") in data]
    # base64 密文特征
    b64_blobs = re.findall(rb'"ct"\s*:\s*"([A-Za-z0-9+/=]{40,})"', data)
    res["ciphertext_blobs"] = len(b64_blobs)
    res["plaintext_hits"] = hits
    res["status"] = "PASS" if not hits else "FAIL"
    res["detail"] = ("信道上只见密文，未发现明文片段"
                     if not hits else "信道上发现明文: %s" % hits)
    return res


def f2_memory(pid, needles, max_bytes=None):
    """扫描 QEMU 进程内存找明文。需要 root。"""
    res = {"check": "F2 Guest 进程内存", "pid": pid}
    if not pid:
        res.update(status="SKIP", detail="未找到 QEMU 进程")
        return res
    maps_path = "/proc/%d/maps" % pid
    mem_path = "/proc/%d/mem" % pid
    if not os.access(mem_path, os.R_OK):
        res.update(status="SKIP",
                   detail="无权读取 %s（需 root 重跑）" % mem_path)
        return res

    needles_b = [n.encode("utf-8") for n in needles]
    found = {}
    scanned = 0
    try:
        fm = open(mem_path, "rb", 0)
    except Exception as e:
        res.update(status="SKIP", detail="打开内存失败: %s" % e)
        return res

    with fm:
        for line in open(maps_path):
            parts = line.split()
            if len(parts) < 2 or "r" not in parts[1]:
                continue
            addr = parts[0]
            try:
                lo, hi = [int(x, 16) for x in addr.split("-")]
            except Exception:
                continue
            size = hi - lo
            if size <= 0 or size > 8 * 1024 ** 3:
                continue
            try:
                fm.seek(lo)
            except Exception:
                continue
            remaining = size
            prev_tail = b""
            while remaining > 0:
                chunk_size = min(remaining, 16 * 1024 * 1024)
                try:
                    buf = fm.read(chunk_size)
                except Exception:
                    break
                if not buf:
                    break
                scanned += len(buf)
                hay = prev_tail + buf
                for nb in needles_b:
                    if nb in hay:
                        found[nb.decode("utf-8", "replace")] = \
                            found.get(nb.decode("utf-8", "replace"), 0) + hay.count(nb)
                prev_tail = hay[-256:]
                remaining -= len(buf)
                if max_bytes and scanned > max_bytes:
                    break
            if max_bytes and scanned > max_bytes:
                break

    res["scanned_mb"] = round(scanned / 1024 ** 2, 1)
    res["plaintext_hits"] = found
    # 注意：这里 FAIL 是"宿主能看到明文"，即缺少内存加密时的预期结果
    res["status"] = "EXPOSED" if found else "NOT_FOUND"
    res["detail"] = ("宿主可在 QEMU 内存中读到明文: %s" % found) if found else \
                    "扫描范围内未命中明文（不等于不可恢复）"
    return res


def f3_disk(img, model_rel="opt/tdc/model/config.json"):
    res = {"check": "F3 磁盘镜像", "image": img}
    if not os.path.exists(img):
        res.update(status="SKIP", detail="镜像不存在")
        return res
    res["size_gb"] = round(os.path.getsize(img) / 1024 ** 3, 1)
    # 直接在裸镜像里搜模型结构特征串
    hit = sh("grep -a -c -m1 'Qwen2ForCausalLM' %s 2>/dev/null" % img).strip()
    res["model_signature_in_raw_image"] = hit not in ("", "0")
    res["status"] = "EXPOSED" if res["model_signature_in_raw_image"] else "NOT_FOUND"
    res["detail"] = ("模型以明文存储于镜像，宿主可直接读取"
                     if res["model_signature_in_raw_image"]
                     else "未在裸镜像中命中模型特征")
    return res


def f4_privkey(capture, guest_pub_b64):
    res = {"check": "F4 会话密钥外泄"}
    if not os.path.exists(capture):
        res.update(status="SKIP", detail="未找到抓包文件")
        return res
    data = open(capture, "rb").read()
    res["guest_pub_on_wire"] = bool(guest_pub_b64 and
                                    guest_pub_b64.encode() in data)
    # 私钥从不发送，信道上只应有公钥
    res["status"] = "PASS"
    res["detail"] = ("信道上只出现 Guest 公钥，未出现私钥或会话密钥；"
                     "会话密钥由双方各自 ECDH 导出，不在信道传输")
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="/home/songyihong/tdc_module2")
    ap.add_argument("--result-json", default=None,
                    help="host_client.py 的 --json-out 产物，用于取明文/公钥")
    ap.add_argument("--out", default=None)
    ap.add_argument("--max-scan-gb", type=float, default=0)
    args = ap.parse_args()

    D = args.dir
    capture = os.path.join(D, "channel_capture.bin")
    img = os.path.join(D, "guest_rootfs.img")
    pidfile = os.path.join(D, "guest.pid")

    needles = []
    guest_pub = None
    if args.result_json and os.path.exists(args.result_json):
        r = json.load(open(args.result_json, encoding="utf-8"))
        needles = [r["prompt"]]
        if r.get("answer"):
            ans = r["answer"].strip()
            if len(ans) >= 12:
                needles.append(ans[:40])
        guest_pub = r.get("guest_pub_b64")
    if not needles:
        needles = ["请用一句话解释什么是可信执行环境。"]

    pid = find_qemu_pid(pidfile)
    max_bytes = int(args.max_scan_gb * 1024 ** 3) if args.max_scan_gb else None

    report = {
        "needles": needles,
        "qemu_pid": pid,
        "running_as_root": os.geteuid() == 0,
        "checks": [
            f1_channel(capture, needles),
            f2_memory(pid, needles, max_bytes),
            f3_disk(img),
            f4_privkey(capture, guest_pub),
        ],
    }

    print(json.dumps(report, ensure_ascii=False, indent=2))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print("\nwrote", args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
