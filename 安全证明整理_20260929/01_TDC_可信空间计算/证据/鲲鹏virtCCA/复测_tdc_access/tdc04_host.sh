set -u
echo "############ TDC-04/07 宿主机（不可信侧）访问测试 ############"
echo "== 宿主上是否存在 NPU 设备节点 =="
ls -l /dev/davinci* /dev/devmm_svm 2>&1 | head -5
echo
echo "== 宿主上 npu-smi 是否可用 =="
if command -v npu-smi >/dev/null 2>&1; then
  echo "npu-smi 已安装: $(command -v npu-smi)"
  # 先落盘再读：npu-smi 在此上下文会挂起，被 timeout 杀掉时管道里的输出会丢
  timeout 20 npu-smi info >/tmp/otp_nsmi.out 2>&1
  echo "  npu-smi info 退出码=$? (124=超时被杀)"
  if [ -s /tmp/otp_nsmi.out ]; then
    head -6 /tmp/otp_nsmi.out | sed 's/^/  /'
  else
    echo "  npu-smi info 无任何输出"
  fi
  rm -f /tmp/otp_nsmi.out
else
  echo "npu-smi: not installed on host"
fi
echo
echo "== 宿主侧驱动占用（vfio-pci 表示已交给虚机独占） =="
for b in 18:00.0 41:00.0; do
  printf "%s -> " "$b"
  lspci -nnk -s $b 2>/dev/null | grep -i "driver in use" | sed 's/^[[:space:]]*//' || echo "?"
done
echo
echo "== 宿主上是否加载了昇腾计算驱动 =="
lsmod 2>/dev/null | grep -iE "devdrv|davinci|drv_pcie" | head -5
echo "(以上为空表示宿主未加载 devdrv 系列模块)"
echo
echo "== 宿主尝试直接读取设备 BAR 空间 =="
for b in 0000:18:00.0 0000:41:00.0; do
  f=/sys/bus/pci/devices/$b/resource0
  if [ -e "$f" ]; then
    out=$(timeout 10 dd if="$f" bs=4096 count=1 of=/dev/null 2>&1 | tail -2 | tr '\n' ' ')
    echo "$b resource0 读取结果: $out"
  else
    echo "$b resource0: 节点不存在"
  fi
done
echo
echo "== IOMMU 分组（一设备一组 = 可独占直通） =="
for b in 0000:18:00.0 0000:41:00.0; do
  g=$(readlink -f /sys/bus/pci/devices/$b/iommu_group 2>/dev/null | xargs basename 2>/dev/null)
  n=$(ls /sys/kernel/iommu_groups/$g/devices 2>/dev/null | wc -l)
  echo "$b -> IOMMU group $g, 组内设备数 $n"
done
echo DONE
