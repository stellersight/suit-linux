#!/bin/sh
# SUIT for Linux end-to-end checks. Runs as root inside a disposable
# container, acting as alice (eligible requester, uid 1001) and bob
# (approver, uid 2000). POSIX sh, so it runs on Debian, Rocky and Alpine.

PASS=0
FAIL=0
ok()   { PASS=$((PASS + 1)); echo "PASS  $1"; }
bad()  { FAIL=$((FAIL + 1)); echo "FAIL  $1"; [ -n "$2" ] && echo "      $2"; }
as_alice() { su -s /bin/sh alice -c "$1" 2>&1; }
as_bob()   { su -s /bin/sh bob -c "echo approver-pass | sudo -S -p '' $1" 2>&1; }
expect_ok()   { out=$(eval "$2"); rc=$?; [ $rc -eq 0 ] && ok "$1" || bad "$1" "rc=$rc: $out"; }
expect_fail() { out=$(eval "$2"); rc=$?; [ $rc -ne 0 ] && ok "$1" || bad "$1" "unexpectedly succeeded: $out"; }
request() { as_alice "sudo -n /usr/bin/suit request $1 --minutes $2 --reason 'e2e test'" | awk '/^r-/{print $1}'; }

echo "== $(. /etc/os-release && echo "$PRETTY_NAME"), kernel $(uname -r)"
echo "== boot_id $(cat /proc/sys/kernel/random/boot_id)"

# 1. Nothing without a grant.
expect_fail "no grant: exec refused" "as_alice 'sudo -n /usr/bin/suit-exec proof.whoami'"
expect_fail "no sudo outside SUIT: alice cannot run id as root" "as_alice 'sudo -n /usr/bin/id -u'"

# 2. A request grants nothing; the requester cannot approve it.
RID=$(request proof.whoami 30)
[ -n "$RID" ] && ok "request created ($RID)" || bad "request created"
expect_fail "pending request: exec refused" "as_alice 'sudo -n /usr/bin/suit-exec proof.whoami'"
expect_fail "requester cannot approve (sudoers)" "as_alice 'sudo -n /usr/bin/suit approve $RID'"

# 3. Approval by someone else; the command runs as root, exactly.
expect_ok "approver approves" "as_bob '/usr/bin/suit approve $RID'"
out=$(as_alice 'sudo -n /usr/bin/suit-exec proof.whoami')
[ "$out" = "0" ] && ok "granted exec runs as uid 0" || bad "granted exec runs as uid 0" "$out"
expect_fail "grant is bound to its action" "as_alice 'sudo -n /usr/bin/suit-exec proof.touch'"
expect_fail "extra arguments refused" "as_alice 'sudo -n /usr/bin/suit-exec proof.whoami --help'"
expect_fail "caller cannot inject LD_PRELOAD" "as_alice 'sudo -n LD_PRELOAD=/tmp/x.so /usr/bin/suit-exec proof.whoami'"

# 4. Standard input is /dev/null.
RID2=$(request proof.stdin 30); as_bob "/usr/bin/suit approve $RID2" >/dev/null
out=$(as_alice "echo SECRET-INPUT | sudo -n /usr/bin/suit-exec proof.stdin")
[ -z "$out" ] && ok "caller's stdin does not reach the command" || bad "caller's stdin does not reach the command" "$out"

# 5. Revocation takes effect on the next call.
expect_ok "requester revokes own grant" "as_alice 'sudo -n /usr/bin/suit revoke $RID --reason done'"
expect_fail "revoked grant: exec refused" "as_alice 'sudo -n /usr/bin/suit-exec proof.whoami'"

# 6. Suspension revokes everything; only root outside sudo can resume.
RID3=$(request proof.touch 30); as_bob "/usr/bin/suit approve $RID3" >/dev/null
expect_ok "approver suspends" "as_bob '/usr/bin/suit suspend --reason e2e-incident'"
expect_fail "suspended: exec refused" "as_alice 'sudo -n /usr/bin/suit-exec proof.touch'"
expect_fail "suspended: new request refused" "as_alice 'sudo -n /usr/bin/suit request proof.touch --minutes 5 --reason x'"
expect_fail "approver cannot resume" "as_bob '/usr/bin/suit resume --reason x'"
expect_ok "root (no sudo) resumes" "/usr/bin/suit resume --reason e2e-cleared 2>&1"
expect_fail "resume does not restore revoked grant" "as_alice 'sudo -n /usr/bin/suit-exec proof.touch'"
[ ! -e /root/suit-proof ] && ok "no root write happened while suspended" || bad "no root write happened while suspended"

# 7. Tampered policy: the broker refuses rather than trusting it.
RID4=$(request proof.touch 30); as_bob "/usr/bin/suit approve $RID4" >/dev/null
chmod g+w /etc/suit/profiles.json
expect_fail "group-writable policy refused" "as_alice 'sudo -n /usr/bin/suit-exec proof.touch'"
chmod g-w /etc/suit/profiles.json
expect_ok "restored policy: granted exec works" "as_alice 'sudo -n /usr/bin/suit-exec proof.touch'"
[ -e /root/suit-proof ] && ok "command wrote where only root can" || bad "command wrote where only root can"

# 8. Tampered installation: the broker refuses to run.
chmod o+w /usr/lib/suit/suitlinux/store.py
expect_fail "world-writable broker module refused" "as_alice 'sudo -n /usr/bin/suit-exec proof.touch'"
chmod o-w /usr/lib/suit/suitlinux/store.py

# 9. A profile whose executable is absent disables only that action.
expect_fail "missing-executable action refused at request" "as_alice 'sudo -n /usr/bin/suit request proof.missing --minutes 5 --reason x'"
out=$(/usr/bin/suit doctor 2>&1)
echo "$out" | grep -q "proof.missing is unavailable" && ok "doctor reports the unavailable action" || bad "doctor reports the unavailable action" "$out"

# 10. doctor finds sudo rights that bypass SUIT.
echo "$out" | grep -q "outside SUIT" && bad "doctor clean with SUIT-only rules" "$out" || ok "doctor clean with SUIT-only rules"
echo 'alice ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/zz-bypass; chmod 0440 /etc/sudoers.d/zz-bypass
out=$(/usr/bin/suit doctor 2>&1); rc=$?
[ $rc -ne 0 ] && echo "$out" | grep -q "outside SUIT" && ok "doctor reports a bypassing sudo rule" || bad "doctor reports a bypassing sudo rule" "$out"
rm -f /etc/sudoers.d/zz-bypass

# 11. Expiry needs no cleanup: wait past a one-minute grant.
RID5=$(request proof.whoami 1); as_bob "/usr/bin/suit approve $RID5" >/dev/null
expect_ok "short grant works before deadline" "as_alice 'sudo -n /usr/bin/suit-exec proof.whoami'"
echo "      waiting 62s for the grant to expire on CLOCK_BOOTTIME..."; sleep 62
expect_fail "expired grant refused without any cleanup job" "as_alice 'sudo -n /usr/bin/suit-exec proof.whoami'"

# 12. The audit chain verifies, and detects tampering.
expect_ok "audit chain verifies" "/usr/bin/suit verify 2>&1"
changed=$(python3 -c "
import sqlite3; db = sqlite3.connect('/var/lib/suit/state.db')
seq = db.execute(\"SELECT MIN(seq) FROM audit_events WHERE record LIKE '%e2e test%'\").fetchone()[0]
n = db.execute(\"UPDATE audit_events SET record = replace(record, 'e2e test', 'rewritten') WHERE seq = ?\", (seq,)).rowcount
db.commit(); print(n)")
[ "$changed" = "1" ] && ok "tamper step changed one stored event" || bad "tamper step changed one stored event" "$changed"
expect_fail "edited audit event detected" "/usr/bin/suit verify 2>&1"

echo "== $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
