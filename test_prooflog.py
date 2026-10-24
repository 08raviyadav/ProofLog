#!/usr/bin/env python3
"""Tests for ProofLog. Standard library only: run with `python -m unittest -v`."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from prooflog import AuditLog, GENESIS_HASH  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
PROOFLOG = os.path.join(HERE, "prooflog.py")


def _tamper(path, index, **changes):
    """Rewrite one entry's fields WITHOUT fixing its hash (simulates an attacker)."""
    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()
    entry = json.loads(lines[index])
    entry.update(changes)
    lines[index] = json.dumps(entry, sort_keys=True) + "\n"
    with open(path, "w", encoding="utf-8") as fh:
        fh.writelines(lines)


class TestAuditLog(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "audit.jsonl")

    def tearDown(self):
        self.tmp.cleanup()

    def _three(self, log=None):
        log = log or AuditLog(self.path)
        log.append("officer.12", "permit.received", {"permit_id": "P-1"})
        log.append("officer.12", "permit.approved", {"permit_id": "P-1"})
        log.append("clerk.03", "permit.issued", {"permit_id": "P-1"})
        return log

    def test_append_and_verify_clean(self):
        log = self._three()
        self.assertEqual(len(log), 3)
        ok, msg = log.verify()
        self.assertTrue(ok, msg)
        entries = log.entries()
        self.assertEqual(entries[0]["prev_hash"], GENESIS_HASH)
        self.assertEqual(entries[1]["prev_hash"], entries[0]["hash"])
        self.assertEqual(entries[2]["prev_hash"], entries[1]["hash"])

    def test_empty_log_verifies(self):
        ok, _ = AuditLog(self.path).verify()
        self.assertTrue(ok)

    def test_tamper_middle_entry_detected(self):
        log = self._three()
        _tamper(self.path, 1, action="permit.rejected")
        ok, msg = log.verify()
        self.assertFalse(ok)
        self.assertIn("1", msg)

    def test_tamper_last_entry_detected(self):
        self._three()
        _tamper(self.path, 2, details={"permit_id": "P-999"})
        ok, _ = AuditLog(self.path).verify()
        self.assertFalse(ok)

    def test_deleted_entry_detected(self):
        self._three()
        with open(self.path, encoding="utf-8") as fh:
            lines = fh.readlines()
        del lines[1]
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
        ok, _ = AuditLog(self.path).verify()
        self.assertFalse(ok)

    def test_reordered_entries_detected(self):
        self._three()
        with open(self.path, encoding="utf-8") as fh:
            lines = fh.readlines()
        lines[0], lines[1] = lines[1], lines[0]
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
        ok, _ = AuditLog(self.path).verify()
        self.assertFalse(ok)

    def test_hmac_key_required_to_verify(self):
        log = AuditLog(self.path, key="correct-horse")
        log.append("officer.12", "permit.approved", {"permit_id": "P-1"})
        ok, _ = AuditLog(self.path, key="correct-horse").verify()
        self.assertTrue(ok)
        # Wrong key: the chain no longer verifies.
        ok, _ = AuditLog(self.path, key="wrong-key").verify()
        self.assertFalse(ok)
        # No key at all: also fails, so a plain-SHA rewrite cannot pass.
        ok, _ = AuditLog(self.path).verify()
        self.assertFalse(ok)

    def test_append_requires_actor_and_action(self):
        with self.assertRaises(ValueError):
            AuditLog(self.path).append("", "permit.approved")
        with self.assertRaises(ValueError):
            AuditLog(self.path).append("officer.12", "")


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "audit.jsonl")

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, *args):
        return subprocess.run([sys.executable, PROOFLOG, *args],
                              capture_output=True, text=True)

    def test_cli_end_to_end_and_tamper(self):
        self.assertEqual(self._run("init", self.path).returncode, 0)
        r = self._run("append", self.path, "--actor", "officer.12",
                      "--action", "permit.approved", "--detail", "permit_id=P-1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self._run("verify", self.path).returncode, 0)
        _tamper(self.path, 0, actor="someone.else")
        self.assertEqual(self._run("verify", self.path).returncode, 1)


if __name__ == "__main__":
    unittest.main()
