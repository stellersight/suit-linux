"""suit-exec: the privileged reference monitor.

Installed root-owned and reached through one static sudoers rule:

    %suit-eligible ALL=(root) NOPASSWD: /usr/sbin/suit-exec

The rule confers nothing on its own. On every invocation the broker:

1. identifies the real caller from sudo (SUDO_UID), never from arguments;
2. resolves the symbolic action name against root-owned policy;
3. requires an active grant for that caller and action, on this boot,
   before its CLOCK_BOOTTIME deadline, with the host not under suspension;
4. writes the audit event and commits it before anything runs;
5. replaces itself with the exact argument vector from policy, in a fixed
   environment, with inherited file descriptors closed.

Users supply an action name only. No command, option, path or operand from
the caller ever reaches the executed program.
"""

import os
import sys
from pathlib import Path
from typing import Dict, Optional

from suitlinux import clock, policy
from suitlinux.store import Store, DEFAULT_DB

SAFE_ENV: Dict[str, str] = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME": "/root",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "SHELL": "/bin/false",
    "TERM": "dumb",
    # systemd and most tools honour these; they make any pager a plain copy.
    "PAGER": "cat",
    "SYSTEMD_PAGER": "cat",
    "SYSTEMD_LESS": "",
    "SYSTEMD_COLORS": "0",
}


class Denied(RuntimeError):
    """Raised when the broker refuses. The message is shown to the caller."""


def caller_uid(environ: Optional[Dict[str, str]] = None, euid: Optional[int] = None) -> int:
    """Identifies the human behind the call.

    The broker must run as root, through sudo. SUDO_UID is set by sudo
    itself, and an unprivileged user cannot reach a root process without
    going through sudo, so it is trustworthy here. Called as root without
    sudo, the caller is root.
    """
    environ = os.environ if environ is None else environ
    euid = os.geteuid() if euid is None else euid
    if euid != 0:
        raise Denied("suit-exec must be run through sudo")
    raw = environ.get("SUDO_UID")
    if raw is None:
        return 0
    if not raw.isdigit():
        raise Denied("malformed SUDO_UID")
    return int(raw)


def authorize(action_name: str, uid: int, store: Store, actions: Dict[str, policy.Action],
              eligibility: Dict[int, policy.Eligibility], boot: str, now_boot: float) -> policy.Action:
    """Decides whether uid may run action_name now. Records the decision either way."""
    action = actions.get(action_name)
    elig = eligibility.get(uid)
    reason = None
    if action is None:
        reason = "unknown action"
    elif action.unavailable:
        reason = f"action unavailable on this host: {action.unavailable}"
    elif elig is None or action_name not in elig.actions:
        reason = "caller is not eligible for this action"
    else:
        grant = store.authorize(uid, action_name, boot, now_boot)
        if grant is None:
            reason = "no active grant"
        else:
            store.record_event("exec.allowed", uid, "success", uid, action_name, boot,
                               {"request": grant["id"], "argv": list(action.argv)})
            return action

    store.record_event("exec.denied", uid, "denied", uid, action_name, boot, {"reason": reason})
    raise Denied(f"denied: {reason}")


def exec_action(action: policy.Action) -> None:  # pragma: no cover - replaces the process
    os.umask(0o022)
    os.chdir("/")
    try:
        max_fd = os.sysconf("SC_OPEN_MAX")
    except (ValueError, OSError):
        max_fd = 1024
    os.closerange(3, max_fd)
    # A fixed argv does not make a program safe if the caller can still feed
    # it input. Standard input is replaced with /dev/null; output and errors
    # stay connected so the caller sees the result.
    devnull = os.open(os.devnull, os.O_RDONLY)
    os.dup2(devnull, 0)
    os.close(devnull)
    os.execve(action.argv[0], list(action.argv), dict(SAFE_ENV))


def verify_own_installation() -> None:  # pragma: no cover - needs a real install
    import suitlinux
    files = [m.__file__ for name, m in list(sys.modules.items())
             if name.startswith("suitlinux") and getattr(m, "__file__", None)]
    files.append(os.path.dirname(suitlinux.__file__))
    policy.verify_installation(files, sys.executable)


def main(argv=None) -> int:  # pragma: no cover - exercised through tests of its parts
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: sudo suit-exec <action>", file=sys.stderr)
        return 2
    try:
        uid = caller_uid()
        verify_own_installation()
        actions, eligibility, _ = policy.load()
        policy.check_state_path(str(DEFAULT_DB))
        store = Store(DEFAULT_DB)
        action = authorize(argv[0], uid, store, actions, eligibility, clock.boot_id(), clock.boot_seconds())
        store.close()
    except (Denied, policy.PolicyError, clock.ClockUnavailable) as e:
        print(f"suit-exec: {e}", file=sys.stderr)
        return 1
    exec_action(action)
    return 0  # unreachable


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
