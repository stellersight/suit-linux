# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 StellerSight Private Limited
"""Generates the suit.audit.v1 shared test vectors.

Run once when the specification changes; the output is committed and then
consumed, unchanged, by both the Python and the PHP test suites. The PHP
implementation is written independently and must reproduce every canonical
byte and hash here, which is what makes the vectors a cross-check rather
than a self-check.

    python -I tools/make_vectors.py > vectors.json
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from suitlinux.audit_v1 import GENESIS, canonicalize, event_hash  # noqa: E402


def event(seq, **over):
    base = {
        "schema": "suit.audit.v1", "source": "suit-linux", "seq": seq, "time": "2026-11-12T03:00:00Z",
        "boot_id": "8f1d3c2a-1111-4222-8333-944455556666", "event": "grant.activated", "actor": 2000,
        "subject": 1001, "object": "service.restart.nginx", "outcome": "success", "details": {},
    }
    base.update(over)
    return base


valid = [
    ("basic", event(1, details={"request": "r-0123456789ab", "duration_s": 900})),
    ("nulls_and_booleans", event(2, boot_id=None, subject=None, object=None, source="drupal",
                                 details={"partial": False, "complete": True, "note": None})),
    ("unicode", event(3, details={"reason": "मरम्मत — café 日本 🙂", "rtl": "שלום"})),
    ("control_characters", event(4, details={"s": "tab\there\nnl\r\x00\x1f\x7f\b\f end"})),
    ("quotes_and_slashes", event(5, details={"s": "a\"b\\c/d</script>"})),
    ("nested_and_arrays", event(6, details={"argv": ["/usr/bin/systemctl", "--no-pager", "restart", "nginx.service"],
                                             "nested": {"z": 1, "a": [1, [2, {"y": "x"}]], "M": "upper sorts first"}})),
    ("integer_boundaries", event(7, details={"max": 2 ** 53 - 1, "min": -(2 ** 53 - 1), "zero": 0, "neg": -1})),
    ("key_order", event(8, details={"b": 1, "a": 2, "B": 3, "_": 4, "0": 5, "a.b": 6, "a:b": 7, "a-b": 8})),
]

out = {
    "spec": "suit.audit.v1",
    "hash": "SHA-256( 'SUIT-AUDIT-V1' 0x00 || previous (32 bytes) || JCS(event) )",
    "rfc8785_string_example": {
        "comment": "RFC 8785 section 3.2.2.2 string; JCS output must match exactly",
        "value": "€$\u000f\nA'B\"\\\\\"/",
        "canonical": '"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"',
    },
    "valid": [],
    "chain": [],
    "invalid": [
        {"name": "float", "json": '{"schema":"suit.audit.v1","seq":1.5}'},
        {"name": "negative_zero", "json": '{"x":-0.0}'},
        {"name": "exponent", "json": '{"x":1e3}'},
        {"name": "unsafe_integer", "json": '{"x":9007199254740992}'},
        {"name": "duplicate_keys", "json": '{"a":1,"a":2}'},
        {"name": "non_ascii_key", "json": '{"café":1}'},
        {"name": "empty_key", "json": '{"":1}'},
        {"name": "lone_surrogate", "json": '{"x":"\\ud800"}'},
        {"name": "nan", "json": '{"x":NaN}'},
    ],
}

for name, ev in valid:
    previous = bytes(range(32))
    out["valid"].append({
        "name": name,
        "event": ev,
        "previous": previous.hex(),
        "canonical": canonicalize(ev).decode("utf-8"),
        "hash": event_hash(ev, previous).hex(),
    })

previous = GENESIS
for i in range(1, 4):
    ev = event(i, event=["request.created", "grant.activated", "exec.allowed"][i - 1], details={"request": "r-chain"})
    digest = event_hash(ev, previous)
    out["chain"].append({"event": ev, "previous": previous.hex(), "hash": digest.hex()})
    previous = digest

json.dump(out, sys.stdout, ensure_ascii=False, indent=2, sort_keys=False)
sys.stdout.write("\n")
