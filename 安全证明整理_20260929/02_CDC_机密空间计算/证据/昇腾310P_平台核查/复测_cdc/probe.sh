set -u
echo "== 设备映射(取正确 card id) =="
npu-smi info -m 2>&1 | head -10
IDS=$(npu-smi info -m 2>&1 | awk 'NR>1 && $1 ~ /^[0-9]+$/ {print $1}' | sort -un)
echo "card ids: $IDS"
echo
for i in $IDS; do
  echo "################ card $i ################"
  for t in board common product work-mode key-manage rootkey pkcs-enable tls-cert tls-cert-period device-share vnpu-mode info-vnpu ecc-enable license; do
    out=$(npu-smi info -t "$t" -i "$i" 2>&1 | head -10)
    echo "### -t $t"
    echo "$out" | sed 's/^/    /'
  done
done
echo DONE
