set -u
echo "############ TDC-04 CVM 内非特权用户访问测试 ############"
echo "== 设备节点权限 =="
ls -l /dev/davinci0 /dev/davinci2 /dev/devmm_svm /dev/davinci_manager 2>&1 | head -5
echo
echo "== 当前用户 =="
id
echo
echo "== 以 nobody 身份尝试读取设备节点 =="
su -s /bin/sh nobody -c 'head -c 16 /dev/davinci0 >/dev/null 2>&1; echo "davinci0 exit=$?"' 2>&1 | tail -1
su -s /bin/sh nobody -c 'head -c 16 /dev/devmm_svm >/dev/null 2>&1; echo "devmm_svm exit=$?"' 2>&1 | tail -1
su -s /bin/sh nobody -c 'head -c 16 /dev/davinci_manager >/dev/null 2>&1; echo "davinci_manager exit=$?"' 2>&1 | tail -1
echo "(exit 非 0 表示被拒绝)"
echo
echo "== 以 nobody 身份尝试 npu-smi =="
su -s /bin/sh nobody -c 'timeout 15 npu-smi info 2>&1 | head -4' 2>&1 | tail -4
echo
echo "== 引擎容器与 cvm-server 容器是否共享设备 =="
docker inspect cvm-server --format '{{json .HostConfig.Devices}}' 2>&1 | head -c 300
echo
echo "== 当前占用 NPU 的进程（应仅引擎） =="
npu-smi info 2>&1 | sed -n '/Process id/,$p' | head -10
echo DONE
