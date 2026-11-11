"""Tests for the suit-linux broker, policy and state store.

These exercise the decision logic on any platform. They do not exercise
sudo, real users, CLOCK_BOOTTIME or reboot; that needs a Linux VM and is
tracked separately.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path

from suitlinux import policy
from suitlinux.broker import Denied, authorize, caller_uid
from suitlinux.cli import sudo_rules_beyond_broker
from suitlinux.store import RISK_NORMAL, RISK_SUSPENDED, Store, StoreError

BOOT = "boot-a"

PROFILES = {
    "schema": "suit.profiles.v1",
    "actions": {
        "service.restart.nginx": {"argv": ["/usr/bin/systemctl", "--no-pager", "restart", "nginx.service"]},
        "service.status.nginx": {"argv": ["/usr/bin/systemctl", "--no-pager", "status", "nginx.service"]},
    },
}
ELIGIBILITY = {
    "schema": "suit.eligibility.v1",
    "approvers": [2000],
    "users": [{"uid": 1001, "actions": ["service.restart.nginx"], "max_duration_seconds": 1800}],
}


class TestPolicy(unittest.TestCase):

    def test_valid_policy_loads(self):
        actions = policy.parse_profiles(PROFILES)
        elig = policy.parse_eligibility(ELIGIBILITY, actions)
        self.assertEqual(("/usr/bin/systemctl", "--no-pager", "restart", "nginx.service"), actions["service.restart.nginx"].argv)
        self.assertIn("service.restart.nginx", elig[1001].actions)

    def _bad(self, argv):
        with self.assertRaises(policy.PolicyError):
            policy.parse_profiles({"schema": "suit.profiles.v1", "actions": {"x": {"argv": argv}}})

    def test_wildcard_arguments_are_refused(self):
        # The pattern behind legacy finding L3: "/usr/bin/tail -n [0-9]* /var/log/*".
        self._bad(["/usr/bin/tail", "-n", "50", "/var/log/*"])

    def test_pager_and_shell_capable_executables_are_refused(self):
        for exe in ("/usr/bin/less", "/usr/bin/vim", "/bin/bash", "/usr/bin/find", "/usr/sbin/tcpdump", "/usr/bin/env"):
            self._bad([exe, "x"])

    def test_relative_or_traversing_executable_is_refused(self):
        self._bad(["systemctl", "status"])
        self._bad(["/usr/bin/../../tmp/x"])

    def test_root_cannot_be_made_eligible(self):
        actions = policy.parse_profiles(PROFILES)
        with self.assertRaises(policy.PolicyError):
            policy.parse_eligibility({"schema": "suit.eligibility.v1", "users": [{"uid": 0, "actions": [], "max_duration_seconds": 600}]}, actions)

    def test_unknown_action_in_eligibility_is_refused(self):
        actions = policy.parse_profiles(PROFILES)
        with self.assertRaises(policy.PolicyError):
            policy.parse_eligibility({"schema": "suit.eligibility.v1", "users": [{"uid": 5, "actions": ["nope"], "max_duration_seconds": 600}]}, actions)

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW") and hasattr(os, "symlink"), "needs O_NOFOLLOW")
    def test_symlinked_policy_file_is_refused(self):
        d = Path(tempfile.mkdtemp())
        real = d / "real.json"
        real.write_text(json.dumps(PROFILES))
        os.symlink(real, d / "profiles.json")
        with self.assertRaises(policy.PolicyError):
            policy.read_protected_json(d / "profiles.json", enforce_ownership=False)


class StoreCase(unittest.TestCase):

    def setUp(self):
        self.store = Store(Path(tempfile.mkdtemp()) / "state.db")

    def tearDown(self):
        self.store.close()


class TestGrantLifecycle(StoreCase):

    def _active(self, duration=600, now=100.0):
        rid = self.store.create_request(1001, "service.restart.nginx", "INC-1", duration, BOOT)
        self.store.approve(rid, 2000, BOOT, now)
        return rid

    def test_request_alone_grants_nothing(self):
        # Legacy finding L4: a request used to issue its own lease.
        self.store.create_request(1001, "service.restart.nginx", "INC-1", 600, BOOT)
        self.assertIsNone(self.store.authorize(1001, "service.restart.nginx", BOOT, 101.0))

    def test_requester_cannot_approve_own_request(self):
        rid = self.store.create_request(1001, "service.restart.nginx", "INC-1", 600, BOOT)
        with self.assertRaises(StoreError):
            self.store.approve(rid, 1001, BOOT, 100.0)

    def test_approved_grant_authorises_within_window(self):
        self._active()
        self.assertIsNotNone(self.store.authorize(1001, "service.restart.nginx", BOOT, 650.0))

    def test_grant_is_bound_to_its_action(self):
        self._active()
        self.assertIsNone(self.store.authorize(1001, "service.status.nginx", BOOT, 150.0))

    def test_grant_expires_without_any_cleanup_job(self):
        # Legacy finding L5: expiry used to leave the sudo rule in place.
        rid = self._active(duration=600, now=100.0)
        self.assertIsNone(self.store.authorize(1001, "service.restart.nginx", BOOT, 700.0))
        self.assertEqual("expired", self.store.get(rid)["state"])

    def test_grant_does_not_survive_reboot(self):
        rid = self._active()
        self.assertIsNone(self.store.authorize(1001, "service.restart.nginx", "boot-b", 5.0))
        self.assertEqual("expired", self.store.get(rid)["state"])

    def test_revocation_is_immediate(self):
        rid = self._active()
        self.store.revoke(rid, 2000, "done early", BOOT)
        self.assertIsNone(self.store.authorize(1001, "service.restart.nginx", BOOT, 150.0))

    def test_suspension_revokes_and_persists(self):
        # Legacy finding L6: suspension used to live in a class variable.
        rid = self._active()
        self.assertEqual(1, self.store.set_risk(RISK_SUSPENDED, 2000, "compromise suspected", BOOT))
        reopened = Store(self.store.path)
        self.assertEqual(RISK_SUSPENDED, reopened.risk_level())
        self.assertIsNone(reopened.authorize(1001, "service.restart.nginx", BOOT, 150.0))
        with self.assertRaises(StoreError):
            reopened.create_request(1001, "service.restart.nginx", "INC-2", 600, BOOT)
        reopened.close()
        self.assertEqual("revoked", self.store.get(rid)["state"])

    def test_resume_does_not_restore_revoked_grants(self):
        self._active()
        self.store.set_risk(RISK_SUSPENDED, 2000, "x", BOOT)
        self.store.set_risk(RISK_NORMAL, 2000, "cleared", BOOT)
        self.assertIsNone(self.store.authorize(1001, "service.restart.nginx", BOOT, 150.0))


class TestAuditChain(StoreCase):

    def test_chain_continues_across_processes(self):
        # Legacy finding L6: the chain head used to reset to zeros each run.
        self.store.create_request(1001, "service.restart.nginx", "INC-1", 600, BOOT)
        second = Store(self.store.path)
        second.create_request(1001, "service.restart.nginx", "INC-2", 600, BOOT)
        self.assertEqual([], second.verify_chain())
        rows = second.db.execute("SELECT seq, prev_hash FROM audit_events ORDER BY seq").fetchall()
        self.assertEqual([1, 2], [r["seq"] for r in rows])
        self.assertNotEqual("0" * 64, rows[1]["prev_hash"])
        second.close()

    def test_edited_record_is_detected(self):
        self.store.create_request(1001, "service.restart.nginx", "INC-1", 600, BOOT)
        self.store.create_request(1001, "service.restart.nginx", "INC-2", 600, BOOT)
        row = self.store.db.execute("SELECT record FROM audit_events WHERE seq = 1").fetchone()
        record = json.loads(row["record"])
        record["details"]["reason"] = "tampered"
        self.store.db.execute("UPDATE audit_events SET record = ? WHERE seq = 1", (json.dumps(record),))
        self.assertTrue(any("seq 1" in p for p in self.store.verify_chain()))

    def test_removed_record_is_detected(self):
        for i in range(3):
            self.store.create_request(1001, "service.restart.nginx", f"INC-{i}", 600, BOOT)
        self.store.db.execute("DELETE FROM audit_events WHERE seq = 2")
        self.assertTrue(self.store.verify_chain())

    def test_state_change_and_event_commit_together(self):
        rid = self.store.create_request(1001, "service.restart.nginx", "INC-1", 600, BOOT)
        before = self.store.db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
        with self.assertRaises(StoreError):
            self.store.approve(rid, 1001, BOOT, 100.0)
        after = self.store.db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
        self.assertEqual(before, after)
        self.assertEqual("pending", self.store.get(rid)["state"])


class TestBroker(StoreCase):

    def setUp(self):
        super().setUp()
        self.actions = policy.parse_profiles(PROFILES)
        self.elig = policy.parse_eligibility(ELIGIBILITY, self.actions)

    def _events(self, name):
        return [json.loads(r["record"]) for r in self.store.db.execute("SELECT record FROM audit_events") if json.loads(r["record"])["event"] == name]

    def test_caller_identity_comes_from_sudo(self):
        self.assertEqual(1001, caller_uid({"SUDO_UID": "1001"}, euid=0))
        self.assertEqual(0, caller_uid({}, euid=0))
        with self.assertRaises(Denied):
            caller_uid({"SUDO_UID": "1001"}, euid=1001)

    def test_runs_only_the_policy_argv(self):
        rid = self.store.create_request(1001, "service.restart.nginx", "INC-1", 600, BOOT)
        self.store.approve(rid, 2000, BOOT, 100.0)
        action = authorize("service.restart.nginx", 1001, self.store, self.actions, self.elig, BOOT, 150.0)
        self.assertEqual(("/usr/bin/systemctl", "--no-pager", "restart", "nginx.service"), action.argv)
        self.assertEqual(1, len(self._events("exec.allowed")))

    def test_denials_are_recorded(self):
        for name, uid in (("service.restart.nginx", 1001), ("service.status.nginx", 1001), ("nope", 1001), ("service.restart.nginx", 4242)):
            with self.assertRaises(Denied):
                authorize(name, uid, self.store, self.actions, self.elig, BOOT, 150.0)
        self.assertEqual(4, len(self._events("exec.denied")))


class TestBypassDetection(unittest.TestCase):

    LISTING = """Matching Defaults entries for alice on host:
    env_reset

User alice may run the following commands on host:
    (root) NOPASSWD: /usr/local/sbin/suit-exec
    (ALL : ALL) ALL
"""

    def test_broad_rule_alongside_broker_is_reported(self):
        self.assertEqual(["(ALL : ALL) ALL"], sudo_rules_beyond_broker(self.LISTING))

    def test_broker_only_is_clean(self):
        self.assertEqual([], sudo_rules_beyond_broker(self.LISTING.replace("    (ALL : ALL) ALL\n", "")))


if __name__ == "__main__":
    unittest.main()


class FakeFS:
    """A minimal lstat for exercising path-integrity checks on any platform."""

    def __init__(self, entries):
        import stat as st
        self.st = st
        self.entries = entries  # path -> (kind, uid, mode)

    def lstat(self, path):
        from types import SimpleNamespace
        if path not in self.entries:
            raise FileNotFoundError(path)
        kind, uid, mode = self.entries[path]
        kinds = {"dir": self.st.S_IFDIR, "file": self.st.S_IFREG, "link": self.st.S_IFLNK}
        return SimpleNamespace(st_mode=kinds[kind] | mode, st_uid=uid)


ROOT_TREE = {
    "/": ("dir", 0, 0o755), "/usr": ("dir", 0, 0o755), "/usr/bin": ("dir", 0, 0o755),
    "/usr/bin/systemctl": ("file", 0, 0o755),
}


class TestExecutableIntegrity(unittest.TestCase):

    def _check(self, entries, path, head=b"\x7fELF"):
        fs = FakeFS(dict(ROOT_TREE, **entries))
        policy.check_executable(path, fs.lstat, lambda p: head)

    def test_root_owned_binary_passes(self):
        self._check({}, "/usr/bin/systemctl")

    def test_binary_owned_by_user_is_refused(self):
        with self.assertRaises(policy.PolicyError):
            self._check({"/usr/bin/systemctl": ("file", 1001, 0o755)}, "/usr/bin/systemctl")

    def test_group_writable_binary_is_refused(self):
        with self.assertRaises(policy.PolicyError):
            self._check({"/usr/bin/systemctl": ("file", 0, 0o775)}, "/usr/bin/systemctl")

    def test_writable_parent_directory_is_refused(self):
        entries = {"/opt": ("dir", 0, 0o777), "/opt/tool": ("file", 0, 0o755)}
        with self.assertRaises(policy.PolicyError):
            self._check(entries, "/opt/tool")

    def test_parent_directory_owned_by_user_is_refused(self):
        entries = {"/opt": ("dir", 1001, 0o755), "/opt/tool": ("file", 0, 0o755)}
        with self.assertRaises(policy.PolicyError):
            self._check(entries, "/opt/tool")

    def test_symlinked_directory_component_is_refused(self):
        # O_NOFOLLOW alone covers only the last component.
        entries = {"/opt": ("link", 0, 0o777), "/opt/tool": ("file", 0, 0o755)}
        with self.assertRaises(policy.PolicyError):
            policy.check_trusted_path("/opt/tool", FakeFS(dict(ROOT_TREE, **entries)).lstat)

    def test_script_with_unsafe_interpreter_is_refused(self):
        entries = {"/usr/bin/helper": ("file", 0, 0o755)}
        with self.assertRaises(policy.PolicyError):
            self._check(entries, "/usr/bin/helper", head=b"#!/bin/bash\necho hi\n")

    def test_script_via_env_is_refused(self):
        entries = {"/usr/bin/helper": ("file", 0, 0o755)}
        with self.assertRaises(policy.PolicyError):
            self._check(entries, "/usr/bin/helper", head=b"#!/usr/bin/env tool\n")

    def test_non_executable_file_is_refused(self):
        with self.assertRaises(policy.PolicyError):
            self._check({"/usr/bin/systemctl": ("file", 0, 0o644)}, "/usr/bin/systemctl")
