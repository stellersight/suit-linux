# Separation of duties (SUIT for Linux 0.3)

Status: implemented in 0.3.0 (specified before implementation). It mirrors SUIT for Drupal's
separation-of-duties policies, so one rule means the same thing on both platforms.

## Policy

An optional, root-owned file `/etc/suit/sod.json`, checked like the other policy
files (root-owned, not writable by group or others, read without following
symlinks):

```json
{
  "schema": "suit.sod.v1",
  "policies": [
    {"name": "deploy-and-audit", "actions": ["service.restart.app", "audit.purge"], "mode": "strict"}
  ]
}
```

- `actions`: two or more action names from `profiles.json`. No user may hold
  active grants for two of them at the same time.
- `mode`: `strict` (refuse) or `warn` (allow, record a warning event). These
  correspond to Drupal's `strict_block` and `audit_warning`.
- No file means no policies, which keeps existing installations working.
- A malformed file, an unknown action, a duplicate name or fewer than two actions
  rejects the **whole** policy set: every request, approval and execution is
  refused with a policy error. The broker never guesses which rules were meant.

## Enforcement

A *conflict* exists for user U and action A when U holds an **active** grant
(approved, unexpired, on this boot, not revoked) for another action B, and a
policy lists both A and B.

| Point | Check | Strict | Warn |
|---|---|---|---|
| Request | Conflicts against U's active grants | Refused | Allowed |
| Approval | Conflicts re-checked in the approval transaction | Refused, request stays pending | Allowed |
| Execution | Conflicts re-checked in the authorisation transaction | Refused, also recorded as `exec.denied` | Allowed |

Every conflict is recorded as `sod.refused` (strict) or `sod.warning` (warn), with
`stage` (`request`, `approval` or `execution`), `policy`, `conflicting_action` and
`conflicting_grant`. A refusal is committed with its event before the caller sees
the error, so refusals are never lost.

- Approval is authoritative. The execution check catches policies added or
  tightened after approval, and races between concurrent approvals.
- Checks run inside the same `BEGIN IMMEDIATE` transaction that writes the
  decision, so two approvals cannot both pass a conflict check.
- `suit doctor` lists policies, and reports users eligible for two actions
  of one strict policy. That is allowed (grants are what conflict), but worth
  knowing.

## Not in scope

- Conflicts with roles or groups outside SUIT. SUIT knows only its own grants.
- Pending requests do not conflict: only active grants do.
- Historical conflicts (holding A yesterday and B today).

## Acceptance tests

1. No `sod.json` behaves exactly as 0.2.
2. Strict policy: a request for B is refused while A is active, and succeeds once A expires or is revoked.
3. Strict: two pending requests (A and B) are both approved concurrently. Only one approval succeeds.
4. Strict policy added after B's approval: executing B while A is active is refused.
5. Warn: everything is allowed, and a `sod.warning` event names the policy.
6. Malformed policy, unknown action, single-action policy and a writable `sod.json` each refuse everything.
7. The audit chain verifies after all of the above.
8. End to end: real sudo, real users, in the container suite.
