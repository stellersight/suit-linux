#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 StellerSight Private Limited
# Phase 2, inside the VM after a real reboot: the grant issued during boot A
# must not authorize anything during boot B, even though its 60-minute
# window has not elapsed by any clock, and even if the wall clock is moved.
PASS=0; FAIL=0
ok()  { PASS=$((PASS + 1)); echo "PASS  $1"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL  $1"; [ -n "${2:-}" ] && echo "      $2"; }
as_alice() { su -s /bin/sh alice -c "$1" 2>&1; }
as_bob()   { su -s /bin/sh bob -c "echo approver-pass | sudo -S -p '' $1" 2>&1; }

RID=$(cat /root/suit-rid)
BOOT_A=$(cat /root/suit-boot-a)
BOOT_B=$(cat /proc/sys/kernel/random/boot_id)
echo "== boot B boot_id $BOOT_B, uptime $(cut -d' ' -f1 /proc/uptime)s"

[ "$BOOT_A" != "$BOOT_B" ] && ok "kernel rebooted: boot_id changed" || bad "kernel rebooted: boot_id changed" "$BOOT_A"

out=$(as_alice "sudo -n /usr/bin/suit-exec proof.whoami"); rc=$?
[ $rc -ne 0 ] && ok "grant from boot A refused after reboot" || bad "grant from boot A refused after reboot" "$out"

state=$(python3 -c "import sqlite3; print(sqlite3.connect('/var/lib/suit/state.db').execute('select state from requests where id=?', ('$RID',)).fetchone()[0])" 2>&1)
[ "$state" = "expired" ] && ok "grant from boot A recorded as expired" || bad "grant from boot A recorded as expired" "state=$state"

# Moving the wall clock must not revive it: expiry is measured on the boot
# clock of the boot that issued it.
date -s '-2 hours' >/dev/null 2>&1
out=$(as_alice "sudo -n /usr/bin/suit-exec proof.whoami"); rc=$?
[ $rc -ne 0 ] && ok "wall clock moved back 2 h: still refused" || bad "wall clock moved back 2 h: still refused" "$out"
date -s '+2 hours' >/dev/null 2>&1

out=$(/usr/bin/suit verify 2>&1); rc=$?
[ $rc -eq 0 ] && ok "audit chain verifies across the reboot" || bad "audit chain verifies across the reboot" "$out"

# The system still works in boot B: a fresh request and approval.
NEW=$(as_alice "sudo -n /usr/bin/suit request proof.whoami --minutes 5 --reason 'after reboot'" | awk '/^r-/{print $1}')
as_bob "/usr/bin/suit approve $NEW" >/dev/null
out=$(as_alice "sudo -n /usr/bin/suit-exec proof.whoami")
[ "$out" = "0" ] && ok "new grant in boot B works" || bad "new grant in boot B works" "$out"

echo "== $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
