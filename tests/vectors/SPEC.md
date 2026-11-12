# suit.audit.v1: audit event format and chain hashing

**Status:** frozen, version 1. **Implementations:** `Drupal\suit\Audit\AuditV1` (PHP) and `suitlinux.audit_v1` (Python). **Conformance:** `tests/fixtures/suit-audit-v1.json`. Both implementations must reproduce every canonical byte and hash in that file, and must refuse every invalid vector.

## 1. Event

An event is a JSON object with exactly these members:

| Member | Type | Meaning |
|---|---|---|
| `schema` | string | Always `"suit.audit.v1"` |
| `source` | string, non-empty | Emitting implementation, e.g. `"drupal"`, `"suit-linux"` |
| `seq` | integer ≥ 1 | Position in this chain; consecutive from 1 |
| `time` | string | UTC, `YYYY-MM-DDTHH:MM:SSZ`. Informational: not a trusted clock |
| `boot_id` | string or null | Host boot identity where meaningful (Linux), else null |
| `event` | string, non-empty | Event type, e.g. `grant.activated` |
| `actor` | integer or null | Who performed it (uid) |
| `subject` | integer or null | Whose access it concerns (uid) |
| `object` | string or null | What it concerns (role, action) |
| `outcome` | `"success"`, `"denied"` or `"failure"` | Result |
| `details` | object | Event-specific data |

The previous hash and the event's own hash are stored alongside the event, not inside it.

## 2. Value profile

Canonical encoding is [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) (JSON Canonicalization Scheme). The profile restricts the values, not the algorithm. For every accepted value, the output is exactly what RFC 8785 specifies.

- **Objects:** keys match `[A-Za-z0-9_.:-]{1,64}`. Keys are ASCII, so sorting by byte is identical to RFC 8785's UTF-16 code-unit order.
- **Strings:** valid Unicode, so lone surrogates are refused.
- **Integers:** between −(2⁵³−1) and 2⁵³−1. Encode larger values as strings.
- **Also permitted:** arrays, `true`, `false` and `null`.
- **Refused:** floats, exponents, negative zero, duplicate keys, and `NaN` or `Infinity`.

Implementations parse untrusted JSON strictly. A parser that silently keeps the last duplicate key (for example PHP's `json_decode`) must not be used on input that will be hashed.

## 3. Hash

```
hash_n = SHA-256( "SUIT-AUDIT-V1" || 0x00 || hash_{n-1} || JCS(event_n) )
```

- `hash_{n-1}` is the predecessor's hash as **32 raw bytes**, not hex.
- The genesis predecessor is 32 zero bytes.
- Hashes are stored and displayed as lowercase hex.

## 4. What verification establishes

A chain that verifies from genesis shows two things: no retained event was edited, and no event between the first and last retained events was removed. The hash is unkeyed. It does **not** show that the newest events were not truncated, or that someone with write access to the store did not rebuild the whole chain. Those properties need external checkpoints, which are not yet specified.

## 5. Relationship to earlier records

Drupal events written before this specification use the module's original hash format, and they remain verifiable with `drush suit:verify`. Records are never rewritten into v1. A future store must record each event's format version and verify it by that version's rules.

## 6. Bounded grants (CAG-INV-3)

Events describing grants refer to grants that cannot exceed 14,400 seconds (4 hours) on any SUIT platform. See `SECURITY.md`.
