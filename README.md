# SUIT for Linux

Just-in-time privileged operations for Linux hosts, through a small local broker.

**Status: pre-release (0.2.0.dev0).** The decision logic has unit tests. The full lifecycle is verified end to end on Debian 12, Rocky Linux 9.3 and Alpine 3.20 in containers, with real sudo, real users and the kernel's `CLOCK_BOOTTIME` (31 checks each; `tests/e2e`). Not yet verified: behaviour across an actual reboot (covered only by unit tests, since a container cannot reboot) and systemd-managed services as targets. Containers share the host kernel, so this is not a substitute for a VM test before production use.

Part of SUIT, StellerSight's access-governance project. The [Drupal module](https://www.drupal.org/project/suit) applies the same model inside Drupal.

---

## How it works

Users never receive a sudo rule for a real command. They receive the right to ask a broker, and the broker runs one exact, root-owned command line for them, and only while an independently approved grant is active.

```
user ── sudo suit request service.restart.nginx ──▶ pending request
approver ── sudo suit approve r-… ──────────────────▶ grant, bound to this boot, N minutes
user ── sudo suit-exec service.restart.nginx ──────▶ broker checks grant ─▶ execve(exact argv)
```

The broker (`suit-exec`) does the following on every call:

1. Identifies the caller from sudo (`SUDO_UID`), never from arguments.
2. Resolves the action name against root-owned policy. The user supplies a name only: no command, option, path or operand.
3. Requires an active grant for that caller and action, on this boot, before its `CLOCK_BOOTTIME` deadline, with the host not suspended.
4. Commits the audit event before anything runs.
5. Executes the policy's exact argument vector with a fixed environment (pagers disabled, no `LD_*`, fixed `PATH`) and inherited file descriptors closed.

Expiry needs no cleanup job. The next call after the deadline, after revocation or after a reboot is refused.

## Guarantees and their limits

| Property | Holds | Limit |
|---|---|---|
| A request grants nothing until someone else approves it | Yes | Approvers are listed by UID in policy |
| Access ends at expiry, revocation or reboot | Yes, checked on each call | Depends on the kernel boot ID and `CLOCK_BOOTTIME`; the broker refuses to run without them |
| Only the policy's exact command runs | Yes | Policy loading refuses wildcards, relative paths, and shells, pagers, editors and other executables that can run arbitrary code. Each executable, every directory above it, and a script's interpreter must be root-owned, free of symlinked directories, and not writable by group or others. A fixed command can still execute code from files an attacker can modify (for example a service's configuration). Review the whole execution chain for each action. |
| Suspension revokes every grant and blocks new ones | Yes, persisted | Any approver can suspend. Only root, logged in directly (console or `su -`, not through sudo), can resume, so one compromised approver cannot reopen the host. Resuming does not restore revoked grants. |
| The broker's own code is trustworthy | Checked on every run | The Python interpreter and every SUIT module must be root-controlled, or the broker and CLI refuse to run |
| A revocation stops a call already authorised | **No** | The authorisation transaction (which commits `exec.allowed`) is the decision point. A revocation that commits after it does not stop that one call, even if the command had not yet started; it takes effect from the next call. Running commands are not interrupted. |
| The executed command receives no input from the caller | Yes | Standard input is `/dev/null`. Output and errors go to the caller. |
| Audit events are hash-linked | Locally tamper-evident | Unkeyed. Detects edited or removed records, not a rebuilt chain or truncation of the newest events. Ship events off the host where that matters. |
| No other sudo path bypasses SUIT | **Not enforced** | `suit doctor` reports eligible users who hold other sudo rights, for example through `wheel`, `sudo` or LDAP. Remove them, or SUIT controls nothing for those users. |

## Install

Run as root. The broker and policy must be root-owned and not writable by anyone else; the broker refuses policy that is not.

```bash
install -d -m 0755 -o root -g root /opt/suit /etc/suit
cp -r suitlinux /opt/suit/ && chown -R root:root /opt/suit && chmod -R go-w /opt/suit
install -m 0755 -o root -g root bin/suit bin/suit-exec /usr/local/sbin/
install -m 0644 -o root -g root etc/profiles.example.json /etc/suit/profiles.json
install -m 0644 -o root -g root etc/eligibility.example.json /etc/suit/eligibility.json
install -d -m 0700 -o root -g root /var/lib/suit
groupadd -f suit-eligible && groupadd -f suit-approvers
install -m 0440 -o root -g root etc/sudoers.suit /etc/sudoers.d/suit && visudo -cf /etc/sudoers.d/suit
```

Then edit `/etc/suit/*.json` and run `sudo suit doctor`.

## Commands

```bash
sudo suit request service.restart.nginx --minutes 15 --reason "INC-8910"
sudo suit approve r-0123456789ab        # approver; never your own request
sudo suit-exec service.restart.nginx    # requester, while the grant is active
sudo suit revoke r-0123456789ab --reason "done"
sudo suit suspend --reason "suspected compromise"   # revokes all, refuses new
su - -c 'suit resume --reason "cleared by IR-42"'  # recovery: root only, not via sudo
sudo suit verify                        # recompute the audit chain
sudo suit doctor                        # find sudo rights that bypass SUIT
```

## History

`legacy/` holds the previous prototype for reference. An audit on 12 November 2026 found that its signatures could be forged (HMAC keys were in the source), its sudo profiles each led to root, a request could approve itself, expired grants kept their sudo rules, and its eBPF programs had no loader. None of that code is used by this version.

## License

GPL-2.0-or-later.
