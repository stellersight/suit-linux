# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 StellerSight Private Limited
"""Separation of duties (docs/separation-of-duties.md), acceptance tests 1-7."""

import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from suitlinux import policy
from suitlinux.broker import Denied, authorize
from suitlinux.store import SodRefusal, Store

BOOT = "boot-a"
A = "deploy.app"
B = "audit.purge"
C = "service.status"

ACTIONS = {name: policy.Action(name=name, argv=("/usr/bin/true",), description="") for name in (A, B, C)}
ELIGIBILITY = {1001: policy.Eligibility(uid=1001, actions=frozenset({A, B, C}), max_duration_seconds=3600)}


def sod(mode="strict"):
    return policy.parse_sod({"schema": "suit.sod.v1",
                             "policies": [{"name": "deploy-and-audit", "actions": [A, B], "mode": mode}]}, ACTIONS)


class SodCase(unittest.TestCase):

    def setUp(self):
        self.path = Path(tempfile.mkdtemp()) / "state.db"
        self.store = Store(self.path)

    def tearDown(self):
        self.store.close()

    def active(self, action, policies=(), now=100.0, duration=600):
        rid = self.store.create_request(1001, action, "INC-1", duration, BOOT, sod=policies, now_boot=now)
        self.store.approve(rid, 2000, BOOT, now, sod=policies)
        return rid

    def events(self, name):
        rows = self.store.db.execute("SELECT record FROM audit_events").fetchall()
        return [json.loads(r[0]) for r in rows if json.loads(r[0])["event"] == name]


class TestPolicyParsing(unittest.TestCase):

    def parse(self, policies):
        return policy.parse_sod({"schema": "suit.sod.v1", "policies": policies}, ACTIONS)

    def test_valid_policy(self):
        (p,) = self.parse([{"name": "p1", "actions": [A, B], "mode": "warn"}])
        self.assertEqual((p.name, p.actions, p.mode), ("p1", frozenset({A, B}), "warn"))

    def test_defects_reject_the_whole_set(self):
        bad = [
            [{"name": "p1", "actions": [A], "mode": "strict"}],                       # one action
            [{"name": "p1", "actions": [A, A], "mode": "strict"}],                    # one distinct action
            [{"name": "p1", "actions": [A, "no.such"], "mode": "strict"}],            # unknown action
            [{"name": "p1", "actions": [A, B], "mode": "block"}],                     # unknown mode
            [{"name": "p1", "actions": [A, B], "mode": "strict"},
             {"name": "p1", "actions": [A, C], "mode": "strict"}],                    # duplicate name
            [{"name": "Bad Name", "actions": [A, B], "mode": "strict"}],              # invalid name
        ]
        for policies in bad:
            with self.subTest(policies=policies), self.assertRaises(policy.PolicyError):
                self.parse(policies)
        with self.assertRaises(policy.PolicyError):
            policy.parse_sod({"schema": "suit.sod.v0", "policies": []}, ACTIONS)

    def test_missing_file_means_no_policies(self):
        def lstat(path):
            raise FileNotFoundError(path)
        self.assertEqual(policy.load_sod(ACTIONS, Path("/etc/suit"), True, lstat), [])


class TestEnforcement(SodCase):

    def test_1_no_policy_behaves_as_before(self):
        self.active(A)
        self.active(B)
        self.assertIsNotNone(self.store.authorize(1001, B, BOOT, 101.0))

    def test_2_strict_refuses_request_while_conflicting_grant_is_active(self):
        p = sod()
        rid_a = self.active(A, p)
        with self.assertRaises(SodRefusal):
            self.store.create_request(1001, B, "INC-2", 600, BOOT, sod=p, now_boot=101.0)
        refused = self.events("sod.refused")
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0]["details"]["conflicting_grant"], rid_a)
        self.assertEqual(refused[0]["details"]["stage"], "request")
        # Once A ends, B may be requested.
        self.store.revoke(rid_a, 1001, "done", BOOT)
        self.store.create_request(1001, B, "INC-2", 600, BOOT, sod=p, now_boot=102.0)

    def test_2b_expired_conflicting_grant_no_longer_counts(self):
        p = sod()
        self.active(A, p, now=100.0, duration=60)
        self.store.create_request(1001, B, "INC-2", 600, BOOT, sod=p, now_boot=161.0)

    def test_2c_unrelated_action_is_not_affected(self):
        p = sod()
        self.active(A, p)
        self.active(C, p)

    def test_3_approval_is_authoritative(self):
        p = sod()
        rid_a = self.store.create_request(1001, A, "INC-1", 600, BOOT, sod=p, now_boot=100.0)
        rid_b = self.store.create_request(1001, B, "INC-2", 600, BOOT, sod=p, now_boot=100.0)
        self.store.approve(rid_a, 2000, BOOT, 100.0, sod=p)
        with self.assertRaises(SodRefusal):
            self.store.approve(rid_b, 2000, BOOT, 101.0, sod=p)
        self.assertEqual(self.store.get(rid_b)["state"], "pending")
        self.assertEqual(self.events("sod.refused")[0]["details"]["stage"], "approval")

    def test_3b_concurrent_approvals_cannot_both_pass(self):
        p = sod()
        rid_a = self.store.create_request(1001, A, "INC-1", 600, BOOT, sod=p, now_boot=100.0)
        rid_b = self.store.create_request(1001, B, "INC-2", 600, BOOT, sod=p, now_boot=100.0)
        outcomes = []

        def approve(rid):
            store = Store(self.path)
            try:
                store.approve(rid, 2000, BOOT, 100.0, sod=p)
                outcomes.append("approved")
            except SodRefusal:
                outcomes.append("refused")
            except sqlite3.OperationalError as e:  # lock timeout would be a test failure
                outcomes.append(f"error {e}")
            finally:
                store.close()

        threads = [threading.Thread(target=approve, args=(rid,)) for rid in (rid_a, rid_b)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(outcomes), ["approved", "refused"])

    def test_4_policy_added_after_approval_is_enforced_at_execution(self):
        self.active(A)
        self.active(B)  # both approved while no policy existed
        with self.assertRaises(SodRefusal):
            self.store.authorize(1001, B, BOOT, 101.0, sod=sod())
        self.assertEqual(self.events("sod.refused")[0]["details"]["stage"], "execution")

    def test_4b_broker_reports_the_refusal(self):
        self.active(A)
        self.active(B)
        with self.assertRaises(Denied) as ctx:
            authorize(B, 1001, self.store, ACTIONS, ELIGIBILITY, BOOT, 101.0, sod())
        self.assertIn("separation of duties", str(ctx.exception))
        self.assertEqual(len(self.events("exec.denied")), 1)

    def test_5_warn_allows_and_records(self):
        p = sod("warn")
        self.active(A, p)
        self.active(B, p)
        self.assertIsNotNone(self.store.authorize(1001, B, BOOT, 101.0, sod=p))
        stages = sorted(e["details"]["stage"] for e in self.events("sod.warning"))
        self.assertEqual(stages, ["approval", "execution", "request"])
        self.assertEqual(self.events("sod.refused"), [])

    def test_7_chain_verifies_after_refusals_and_warnings(self):
        self.active(A, sod())
        with self.assertRaises(SodRefusal):
            self.store.create_request(1001, B, "INC-2", 600, BOOT, sod=sod(), now_boot=101.0)
        self.active(C, sod("warn"))
        self.assertEqual(self.store.verify_chain(), [])



class TestDoctorReport(unittest.TestCase):

    def test_reports_policies_and_doubly_eligible_users(self):
        from suitlinux.cli import sod_report
        lines = sod_report(sod(), ELIGIBILITY)
        self.assertIn("deploy-and-audit (strict)", lines[0])
        self.assertTrue(any("uid 1001 is eligible for 2" in line for line in lines))
        self.assertIn("no policies", sod_report((), ELIGIBILITY)[0])


if __name__ == "__main__":
    unittest.main()
