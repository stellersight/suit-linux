#!/bin/sh
# Drives the VM: boot, install SUIT and issue a grant (phase 1), reboot the
# guest kernel, then check the grant is dead (phase 2).
set -eu
IMG_URL=https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2
CACHE=/cache
WORK=/work
mkdir -p "$CACHE" "$WORK"
[ -s "$CACHE/base.qcow2" ] || curl -sSLf -o "$CACHE/base.qcow2" "$IMG_URL"
qemu-img create -q -f qcow2 -F qcow2 -b "$CACHE/base.qcow2" "$WORK/disk.qcow2" 8G

ssh-keygen -q -t ed25519 -N '' -f "$WORK/key"
cat > "$WORK/user-data" <<EOF
#cloud-config
ssh_authorized_keys:
  - $(cat "$WORK/key.pub")
EOF
printf 'instance-id: suit-vm\nlocal-hostname: suit-vm\n' > "$WORK/meta-data"
cloud-localds "$WORK/seed.iso" "$WORK/user-data" "$WORK/meta-data"

ACCEL=tcg
[ -e /dev/kvm ] && ACCEL=kvm
qemu-system-x86_64 -accel "$ACCEL" -m 1536 -smp 2 -nographic \
  -drive file="$WORK/disk.qcow2",if=virtio -drive file="$WORK/seed.iso",if=virtio,format=raw \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:2222-:22 -device virtio-net-pci,netdev=n0 \
  > "$WORK/console.log" 2>&1 &
QEMU=$!

SSH="ssh -q -i $WORK/key -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 debian@127.0.0.1"
wait_up() {
  i=0
  until $SSH true 2>/dev/null; do
    i=$((i + 1)); [ $i -gt 180 ] && { echo "VM did not come up"; tail -30 "$WORK/console.log"; kill $QEMU; exit 2; }
    sleep 5
  done
}

echo "== booting Debian 12 under QEMU ($ACCEL)"
wait_up
tar -C /src -cf - suitlinux bin etc tests | $SSH 'sudo mkdir -p /root/suit && sudo tar -C /root/suit -xf -'
$SSH 'sudo sh /root/suit/tests/vm/guest-phase1.sh'

echo "== rebooting the guest kernel"
$SSH 'sudo systemctl reboot' || true
sleep 15
wait_up
set +e
$SSH 'sudo sh /root/suit/tests/vm/guest-phase2.sh'
rc=$?
$SSH 'sudo systemctl poweroff' >/dev/null 2>&1
wait $QEMU 2>/dev/null
exit $rc
