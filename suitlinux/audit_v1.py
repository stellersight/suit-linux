"""suit.audit.v1: canonical encoding and chain hashing.

This module and the PHP class Drupal\\suit\\Audit\\AuditV1 implement the same
specification (docs/spec/suit-audit-v1.md in the Drupal module) and are both
tested against one shared set of vectors, so an event hashed on Linux can be
verified in Drupal and the reverse.

Canonical encoding is RFC 8785 (JCS) restricted to a value profile:
objects with ASCII keys, arrays, strings, booleans, null and integers in the
IEEE 754 safe range. Floats are refused rather than canonicalised, which
removes the hard part of JCS without departing from it: every accepted value
encodes exactly as RFC 8785 specifies.

    hash = SHA-256( "SUIT-AUDIT-V1" 0x00 || previous_hash (32 raw bytes) || JCS(event) )

The genesis previous_hash is 32 zero bytes.
"""

import hashlib
import json
import re
from typing import Any, Dict, Tuple

DOMAIN = b"SUIT-AUDIT-V1\x00"
GENESIS = bytes(32)
MAX_SAFE_INTEGER = 2 ** 53 - 1
KEY_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")

EVENT_FIELDS = ("schema", "source", "seq", "time", "boot_id", "event", "actor", "subject", "object", "outcome", "details")
OUTCOMES = ("success", "denied", "failure")
TIME_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

_SHORT_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


class ProfileError(ValueError):
    """Raised when a value is outside the suit.audit.v1 value profile."""


def _encode_string(s: str) -> str:
    try:
        s.encode("utf-8")
    except UnicodeEncodeError as e:
        raise ProfileError("strings must be valid Unicode (lone surrogate found)") from e
    out = ['"']
    for ch in s:
        if ch in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[ch])
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _encode(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise ProfileError(f"integer {value} is outside the safe range; encode it as a string")
        return str(value)
    if isinstance(value, float):
        raise ProfileError("floating-point numbers are not permitted")
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_encode(v) for v in value) + "]"
    if isinstance(value, dict):
        for k in value:
            if not isinstance(k, str) or not KEY_PATTERN.match(k):
                raise ProfileError(f"object key {k!r} must match {KEY_PATTERN.pattern}")
        # Keys are ASCII, so code-point order equals RFC 8785's UTF-16 code-unit order.
        return "{" + ",".join(_encode_string(k) + ":" + _encode(value[k]) for k in sorted(value)) + "}"
    raise ProfileError(f"unsupported type {type(value).__name__}")


def canonicalize(value: Any) -> bytes:
    """Returns the RFC 8785 encoding of a profile-conforming value, as UTF-8."""
    return _encode(value).encode("utf-8")


def strict_loads(text: str) -> Any:
    """Parses JSON, refusing duplicate keys, floats and the non-standard NaN/Infinity."""
    def pairs(items):
        obj = {}
        for k, v in items:
            if k in obj:
                raise ProfileError(f"duplicate key {k!r}")
            obj[k] = v
        return obj

    def no_float(token):
        raise ProfileError(f"floating-point number {token} is not permitted")

    def no_constant(token):
        raise ProfileError(f"{token} is not valid JSON")

    return json.loads(text, object_pairs_hook=pairs, parse_float=no_float, parse_constant=no_constant)


def validate_event(event: Dict[str, Any]) -> None:
    """Checks the suit.audit.v1 event shape. Raises ProfileError."""
    if set(event) != set(EVENT_FIELDS):
        missing = set(EVENT_FIELDS) - set(event)
        extra = set(event) - set(EVENT_FIELDS)
        raise ProfileError(f"event fields: missing {sorted(missing)}, unexpected {sorted(extra)}")
    if event["schema"] != "suit.audit.v1":
        raise ProfileError("schema must be suit.audit.v1")
    if not isinstance(event["seq"], int) or isinstance(event["seq"], bool) or event["seq"] < 1:
        raise ProfileError("seq must be a positive integer")
    if not isinstance(event["time"], str) or not TIME_PATTERN.match(event["time"]):
        raise ProfileError("time must be UTC in the form YYYY-MM-DDTHH:MM:SSZ")
    if event["outcome"] not in OUTCOMES:
        raise ProfileError(f"outcome must be one of {OUTCOMES}")
    if not isinstance(event["details"], dict):
        raise ProfileError("details must be an object")
    for field in ("source", "event"):
        if not isinstance(event[field], str) or not event[field]:
            raise ProfileError(f"{field} must be a non-empty string")
    for field in ("actor", "subject"):
        if event[field] is not None and (not isinstance(event[field], int) or isinstance(event[field], bool)):
            raise ProfileError(f"{field} must be an integer or null")
    for field in ("boot_id", "object"):
        if event[field] is not None and not isinstance(event[field], str):
            raise ProfileError(f"{field} must be a string or null")
    canonicalize(event)


def event_hash(event: Dict[str, Any], previous: bytes) -> bytes:
    """Returns the 32-byte chain hash of an event given its predecessor's hash."""
    if len(previous) != 32:
        raise ProfileError("previous hash must be exactly 32 bytes")
    validate_event(event)
    return hashlib.sha256(DOMAIN + previous + canonicalize(event)).digest()


def verify_chain(entries) -> Tuple[bool, list]:
    """Verifies (event, stored_hex_hash) pairs in order from genesis."""
    problems = []
    previous = GENESIS
    for i, (event, stored) in enumerate(entries, start=1):
        try:
            digest = event_hash(event, previous)
        except ProfileError as e:
            problems.append(f"entry {i}: {e}")
            break
        if digest.hex() != stored:
            problems.append(f"entry {i}: hash mismatch")
        previous = bytes.fromhex(stored) if len(stored) == 64 else digest
    return (not problems), problems
