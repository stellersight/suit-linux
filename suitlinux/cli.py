"""suit: request, approve, deny, revoke, suspend, status and verify.

Run through sudo; the caller's identity comes from sudo, never from flags.

    sudo suit request <action> --minutes 30 --reason "INC-8910 restart nginx"
    sudo suit approve <request-id>          # approvers only, never your own
    sudo suit deny <request-id> --reason ...
    sudo suit revoke <request-id> --reason ...
    sudo suit suspend --reason ...          # revokes every grant, refuses new ones
    sudo suit resume --reason ...
    sudo suit status
    sudo suit verify                        # recompute the audit chain
    sudo suit doctor                        # look for sudo rights that bypass SUIT
"""

import argparse
import json
import subprocess
import sys
from typing import List

from suitlinux import clock, policy
from suitlinux.broker import Denied, caller_uid
from suitlinux.store import DEFAULT_DB, RISK_NORMAL, RISK_SUSPENDED, Store, StoreError

BROKER_PATH = "/usr/local/sbin/suit-exec"


def _boot_or_none():
    try:
        return clock.boot_id()
    except clock.ClockUnavailable:
        return None


def cmd_request(args, uid, store, actions, eligibility, approvers) -> int:
    elig = eligibility.get(uid)
    if elig is None or args.action not in elig.actions:
        raise Denied(f"uid {uid} is not eligible for {args.action}")
    seconds = args.minutes * 60
    if seconds > elig.max_duration_seconds:
        raise Denied(f"the maximum for this action is {elig.max_duration_seconds // 60} minutes")
    rid = store.create_request(uid, args.action, args.reason, seconds, _boot_or_none())
    print(f"{rid} pending approval: {args.action} for {args.minutes} minutes")
    return 0


def cmd_approve(args, uid, store, actions, eligibility, approvers) -> int:
    if uid not in approvers:
        raise Denied(f"uid {uid} is not an approver")
    req = store.approve(args.request, uid, clock.boot_id(), clock.boot_seconds())
    print(f"{args.request} active: uid {req['uid']} may run {req['action']} for {req['duration_s'] // 60} minutes, until reboot at the latest")
    return 0


def cmd_deny(args, uid, store, actions, eligibility, approvers) -> int:
    if uid not in approvers:
        raise Denied(f"uid {uid} is not an approver")
    store.deny(args.request, uid, args.reason, _boot_or_none())
    print(f"{args.request} denied")
    return 0


def cmd_revoke(args, uid, store, actions, eligibility, approvers) -> int:
    req = store.get(args.request)
    if req is None:
        raise Denied(f"no request {args.request}")
    if uid not in approvers and uid != req["uid"]:
        raise Denied("only an approver or the requester can revoke")
    store.revoke(args.request, uid, args.reason, _boot_or_none())
    print(f"{args.request} revoked; the next suit-exec call will be refused")
    return 0


def cmd_risk(args, uid, store, actions, eligibility, approvers, level) -> int:
    if uid not in approvers and uid != 0:
        raise Denied("only an approver or root can change the risk level")
    closed = store.set_risk(level, uid, args.reason, _boot_or_none())
    print(f"risk level {level}" + (f"; {closed} request(s) closed" if closed else ""))
    return 0


def cmd_status(args, uid, store, actions, eligibility, approvers) -> int:
    rows = store.list_requests(["pending", "active"])
    print(json.dumps({
        "risk_level": store.risk_level(),
        "open_requests": [dict(r) for r in rows],
    }, indent=2, default=str))
    return 0


def cmd_verify(args, uid, store, actions, eligibility, approvers) -> int:
    problems = store.verify_chain()
    count = store.db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
    if problems:
        print(f"audit chain INCONSISTENT ({count} events):")
        for p in problems:
            print(f"  {p}")
        return 1
    print(f"audit chain consistent: {count} events. Unkeyed: this detects edited or removed records, "
          f"not a rebuilt chain or truncation of the newest events.")
    return 0


def sudo_rules_beyond_broker(listing: str) -> List[str]:
    """Returns sudo -l lines that grant something other than the SUIT broker.

    Bypass E: an eligible user who also holds a broad rule elsewhere (wheel,
    sudo, LDAP) does not need SUIT at all, which makes SUIT's controls moot.
    """
    findings = []
    in_rules = False
    for line in listing.splitlines():
        stripped = line.strip()
        if "may run the following commands" in stripped:
            in_rules = True
            continue
        if not in_rules or not stripped or not stripped.startswith("("):
            continue
        commands = stripped.split(")", 1)[1].strip()
        for tag in ("NOPASSWD:", "PASSWD:", "SETENV:", "NOSETENV:"):
            commands = commands.replace(tag, "")
        if not all(c.strip() in (BROKER_PATH, "/usr/local/sbin/suit") or c.strip().startswith("/usr/local/sbin/suit ")
                   for c in commands.split(",")):
            findings.append(stripped)
    return findings


def cmd_doctor(args, uid, store, actions, eligibility, approvers) -> int:
    import pwd  # POSIX only

    exit_code = 0
    for elig_uid in sorted(eligibility):
        try:
            name = pwd.getpwuid(elig_uid).pw_name
        except KeyError:
            print(f"uid {elig_uid}: no such user")
            exit_code = 1
            continue
        out = subprocess.run(["sudo", "-n", "-l", "-U", name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
        extra = sudo_rules_beyond_broker(out.stdout)
        if extra:
            exit_code = 1
            print(f"{name} (uid {elig_uid}) holds sudo rights outside SUIT, which bypass it:")
            for line in extra:
                print(f"    {line}")
        else:
            print(f"{name} (uid {elig_uid}): only SUIT broker rules")
    return exit_code


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="suit", description="SUIT for Linux: just-in-time privileged operations")
    sub = p.add_subparsers(dest="command", required=True)
    r = sub.add_parser("request"); r.add_argument("action"); r.add_argument("--minutes", type=int, required=True); r.add_argument("--reason", required=True)
    a = sub.add_parser("approve"); a.add_argument("request")
    d = sub.add_parser("deny"); d.add_argument("request"); d.add_argument("--reason", required=True)
    v = sub.add_parser("revoke"); v.add_argument("request"); v.add_argument("--reason", required=True)
    s = sub.add_parser("suspend"); s.add_argument("--reason", required=True)
    u = sub.add_parser("resume"); u.add_argument("--reason", required=True)
    sub.add_parser("status"); sub.add_parser("verify"); sub.add_parser("doctor")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        uid = caller_uid()
        actions, eligibility, approvers = policy.load()
        store = Store(DEFAULT_DB)
        handlers = {
            "request": cmd_request, "approve": cmd_approve, "deny": cmd_deny, "revoke": cmd_revoke,
            "status": cmd_status, "verify": cmd_verify, "doctor": cmd_doctor,
        }
        if args.command == "suspend":
            return cmd_risk(args, uid, store, actions, eligibility, approvers, RISK_SUSPENDED)
        if args.command == "resume":
            return cmd_risk(args, uid, store, actions, eligibility, approvers, RISK_NORMAL)
        return handlers[args.command](args, uid, store, actions, eligibility, approvers)
    except (Denied, StoreError, policy.PolicyError, clock.ClockUnavailable) as e:
        print(f"suit: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
