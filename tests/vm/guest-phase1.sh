#!/bin/sh
# Phase 1, inside the VM before reboot: install SUIT as the e2e image does,
# issue an approved grant, prove it works, and record the boot ID.
set -eu
cd /root/suit
apt-get update -qq >/dev/null && apt-get install -y -qq sudo python3 passwd >/dev/null
install -d /usr/lib/suit /etc/suit
cp -r suitlinux /usr/lib/suit/
cp bin/suit bin/suit-exec /usr/bin/
cp etc/sudoers.suit /etc/sudoers.d/suit
cp tests/e2e/profiles.json tests/e2e/eligibility.json /etc/suit/
find /usr/lib/suit -name __pycache__ -prune -exec rm -rf {} +
chown -R root:root /usr/lib/suit /etc/suit /usr/bin/suit /usr/bin/suit-exec
chmod -R go-w /usr/lib/suit /etc/suit; chmod 0755 /usr/bin/suit /usr/bin/suit-exec
chmod 0440 /etc/sudoers.d/suit; visudo -cf /etc/sudoers.d/suit >/dev/null
install -d -m 0700 /var/lib/suit
groupadd -f suit-eligible; groupadd -f suit-approvers
id alice >/dev/null 2>&1 || useradd -m -u 1001 -G suit-eligible alice
id bob >/dev/null 2>&1 || useradd -m -u 2000 -G suit-approvers bob
echo 'bob:approver-pass' | chpasswd

as_alice() { su -s /bin/sh alice -c "$1" 2>&1; }
as_bob()   { su -s /bin/sh bob -c "echo approver-pass | sudo -S -p '' $1" 2>&1; }

RID=$(as_alice "sudo -n /usr/bin/suit request proof.whoami --minutes 60 --reason 'vm reboot test'" | awk '/^r-/{print $1}')
[ -n "$RID" ] || { echo "FAIL  request not created"; exit 1; }
as_bob "/usr/bin/suit approve $RID" >/dev/null
out=$(as_alice "sudo -n /usr/bin/suit-exec proof.whoami")
[ "$out" = "0" ] || { echo "FAIL  approved grant did not run as root: $out"; exit 1; }
echo "PASS  boot A: approved 60-minute grant runs as root ($RID)"

echo "$RID" > /root/suit-rid
cat /proc/sys/kernel/random/boot_id > /root/suit-boot-a
echo "== boot A boot_id $(cat /root/suit-boot-a), uptime $(cut -d' ' -f1 /proc/uptime)s"
