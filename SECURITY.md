# Security policy

SUIT for Linux runs as root through sudo. A flaw in it can be a privilege
escalation on every host that uses it, so reports are handled first.

## Reporting a vulnerability

Do not open a public issue for a security problem. Report it privately to
**security@stellersight.com** with:

- the version or commit, distribution and sudo version;
- the profile and eligibility files involved, with secrets removed;
- the steps to reproduce, and what an attacker gains.

We acknowledge reports within three working days, aim to fix confirmed
vulnerabilities within 30 days, and credit reporters who wish to be named.
Please allow us to release a fix before disclosure.

## What is in scope

- Running a command, or a different command, without an active grant.
- A grant outliving its expiry, revocation, suspension or a reboot.
- A requester approving their own request.
- Steering the broker through its environment, arguments, standard input,
  file descriptors or policy files.
- Audit records that can be changed or removed without `suit verify`
  reporting it.

## What is not in scope

These are documented limits, not vulnerabilities (see the README):

- Other sudo rules that bypass SUIT. `suit doctor` reports them; removing
  them is the administrator's job.
- A command that executes files an attacker can modify, such as a
  service's configuration. Review each action's execution chain.
- A rebuilt audit chain by someone with root: the chain is unkeyed and
  tamper-evident, not immutable.
- A call already authorised when a revocation commits.
