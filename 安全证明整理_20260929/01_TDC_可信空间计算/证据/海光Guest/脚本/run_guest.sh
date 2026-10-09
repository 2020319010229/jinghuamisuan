#!/bin/bash
# 启动 TDC Guest：virtio 根盘 + virtio-serial 密态信道
# 以普通用户运行（用户需在 kvm 组），这样 unix socket 属主正确，宿主客户端可直接连。
D=/home/songyihong/tdc_module2
IMG=$D/guest_rootfs.img
SOCK=$D/tdc.chan0.sock
CONSOLE=$D/guest-console.log
PIDF=$D/guest.pid

MEM=${TDC_MEM:-8192}
CPUS=${TDC_CPUS:-8}

# 清理上一轮
if [ -f "$PIDF" ]; then
  OLD=$(cat "$PIDF")
  kill "$OLD" 2>/dev/null && sleep 2
  kill -9 "$OLD" 2>/dev/null
  rm -f "$PIDF"
fi
rm -f "$SOCK" "$CONSOLE"

echo "[run_guest] image   : $IMG"
echo "[run_guest] channel : $SOCK"
echo "[run_guest] console : $CONSOLE"
echo "[run_guest] mem=${MEM}MB cpus=${CPUS}"

qemu-kvm \
  -enable-kvm -machine q35 -cpu host \
  -m "$MEM" -smp "$CPUS" \
  -drive file="$IMG",format=raw,if=virtio,cache=writeback \
  -kernel "$D/vmlinuz-6.6.0-euler" \
  -initrd "$D/initramfs-guest.img" \
  -append "root=LABEL=tdcroot rw console=ttyS0 selinux=0 enforcing=0 rd.timeout=60" \
  -chardev socket,id=tdcchan,path="$SOCK",server=on,wait=off \
  -device virtio-serial-pci,id=vser0 \
  -device virtserialport,bus=vser0.0,chardev=tdcchan,name=tdc.chan0 \
  -display none \
  -serial file:"$CONSOLE" \
  -monitor none \
  -pidfile "$PIDF" \
  -no-reboot \
  &

sleep 3
if [ -f "$PIDF" ]; then
  echo "[run_guest] started pid=$(cat $PIDF)"
else
  echo "[run_guest] FAILED to start"
  exit 1
fi
