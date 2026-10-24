#!/usr/bin/env python3
"""ProofLog — a tamper-evident audit log in a single file, zero dependencies.

Why this exists
---------------
Public-service software (permits, payments, registries, queues) makes
decisions that affect real people. When someone later asks "who approved
this, and was the record changed afterwards?", the honest answer needs
more than a database row that anyone with write access can quietly edit.

ProofLog gives every record a hash chain: each entry stores the hash of
the entry before it, so changing, deleting, or reordering *any* entry
breaks every hash after it. Verification is one command, and it tells
you exactly which entry is the first broken one.

What it is NOT
--------------
A hash chain is tamper-*evident*, not tamper-*proof*. Anyone holding the
log file can rewrite the whole chain from scratch — that is why the
optional HMAC key exists (without the key, a rewritten chain will not
verify), and why, for serious use, verified copies/hashes of the log
should be published or archived somewhere the writer cannot rewrite.
ProofLog is deliberately small: it is a building block for audit
trails, not a database, not a blockchain, and not a legal guarantee.

Storage format
--------------
One JSON object per line (JSONL), one entry per line::

    {"index": 0, "timestamp": "2026-10-24T08:00:00Z", "actor": "officer.12",
     "action": "permit.approved", "details": {"permit_id": "P-1042"},
     "prev_hash": "0000...0000", "hash": "9f2c..."}

``hash`` is SHA-256 over the canonical JSON of every other field, or
HMAC-SHA-256 with the secret key when one is supplied.

Usage (library)::

    from prooflog import AuditLog
    log = AuditLog("audit.jsonl")
    log.append(actor="officer.12", action="permit.approved",
               details={"permit_id": "P-1042"})
    ok, message = log.verify()
    assert ok, message

Usage (CLI)::

    python prooflog.py init audit.jsonl
    python prooflog.py append audit.jsonl --actor officer.12 \\
        --action permit.approved --detail permit_id=P-1042
    python prooflog.py verify audit.jsonl
    python prooflog.py show audit.jsonl

The HMAC key is read from ``PROOFLOG_KEY`` or ``--key``. Prefer the
environment variable: a ``--key`` value ends up in shell history.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timezone

__version__ = "0.1.0"
GENESIS_HASH = "0" * 64


# ---------------------------------------------------------------- helpers

def _canonical(obj) -> bytes:
    """One deterministic byte representation for hashing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _entry_hash(entry: dict, key: str | None) -> str:
    payload = {k: v for k, v in entry.items() if k != "hash"}
    data = _canonical(payload)
    if key is None:
        return hashlib.sha256(data).hexdigest()
    return hmac.new(key.encode("utf-8"), data, hashlib.sha256).hexdigest()


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_details(text: str | None, pairs: list[str]) -> dict:
    details: dict = {}
    if text:
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"--details is not valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ValueError("--details must be a JSON object, e.g. '{\"id\": 42}'")
        details.update(parsed)
    for pair in pairs:
        if "=" not in pair:
            raise ValueError(f"--detail needs key=value, got: {pair!r}")
        k, v = pair.split("=", 1)
        details[k] = v
    return details


# ---------------------------------------------------------------- core

class AuditLog:
    """An append-only, hash-chained log stored as JSONL."""

    def __init__(self, path: str, key: str | None = None):
        self.path = path
        self.key = key

    # -- reading ----------------------------------------------------
    def entries(self) -> list[dict]:
        if not os.path.exists(self.path):
            return []
        out = []
        with open(self.path, "r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"line {lineno} is not valid JSON: {exc}") from exc
                if not isinstance(entry, dict):
                    raise ValueError(f"line {lineno} is not a JSON object")
                out.append(entry)
        return out

    def __len__(self) -> int:
        return len(self.entries())

    # -- writing ----------------------------------------------------
    def append(self, actor: str, action: str, details: dict | None = None,
               timestamp: str | None = None) -> dict:
        if not actor or not action:
            raise ValueError("actor and action are both required")
        existing = self.entries()
        prev_hash = existing[-1]["hash"] if existing else GENESIS_HASH
        entry = {
            "index": len(existing),
            "timestamp": timestamp or _utcnow(),
            "actor": actor,
            "action": action,
            "details": details or {},
            "prev_hash": prev_hash,
        }
        entry["hash"] = _entry_hash(entry, self.key)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n")
        return entry

    # -- verification ----------------------------------------------
    def verify(self) -> tuple[bool, str]:
        """Return (True, summary) or (False, first problem found)."""
        try:
            entries = self.entries()
        except ValueError as exc:
            return False, str(exc)
        expected_prev = GENESIS_HASH
        for entry in entries:
            if entry.get("prev_hash") != expected_prev:
                return False, (
                    f"entry {entry.get('index')}: prev_hash does not match "
                    f"the previous entry's hash (entry deleted, reordered, "
                    f"or rewritten)"
                )
            if entry.get("hash") != _entry_hash(entry, self.key):
                return False, (
                    f"entry {entry.get('index')}: hash mismatch — this "
                    f"entry was changed after it was written"
                )
            expected_prev = entry["hash"]
        # Sequential-index check, reported after hash checks so the most
        # informative failure wins; a broken index alone also fails.
        for position, entry in enumerate(entries):
            if entry.get("index") != position:
                return False, (
                    f"entry at position {position} has index "
                    f"{entry.get('index')!r} (entries out of order or renumbered)"
                )
        noun = "entry" if len(entries) == 1 else "entries"
        return True, f"OK: {len(entries)} {noun}, chain intact"


# ---------------------------------------------------------------- CLI

def _get_key(args) -> str | None:
    return args.key or os.environ.get("PROOFLOG_KEY")


def _cmd_init(args) -> int:
    if os.path.exists(args.path):
        with open(args.path, "r", encoding="utf-8") as fh:
            if fh.read().strip() and not args.force:
                print(f"error: {args.path} already has entries (use --force to reset)",
                      file=sys.stderr)
                return 2
    open(args.path, "w", encoding="utf-8").close()
    print(f"initialised empty log: {args.path}")
    return 0


def _cmd_append(args) -> int:
    try:
        details = _parse_details(args.details, args.detail)
        entry = AuditLog(args.path, _get_key(args)).append(
            actor=args.actor, action=args.action, details=details)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"appended entry {entry['index']}: {entry['actor']} {entry['action']} "
          f"(hash {entry['hash'][:12]}...)")
    return 0


def _cmd_verify(args) -> int:
    ok, message = AuditLog(args.path, _get_key(args)).verify()
    print(("PASS: " if ok else "FAIL: ") + message)
    return 0 if ok else 1


def _cmd_show(args) -> int:
    try:
        entries = AuditLog(args.path, _get_key(args)).entries()
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not entries:
        print("(empty log)")
        return 0
    for e in entries:
        if args.json:
            print(json.dumps(e, sort_keys=True, ensure_ascii=False))
        else:
            print(f"[{e.get('index')}] {e.get('timestamp')} "
                  f"{e.get('actor')} {e.get('action')} "
                  f"details={json.dumps(e.get('details', {}), ensure_ascii=False)} "
                  f"hash={str(e.get('hash'))[:12]}...")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="prooflog",
        description="Tamper-evident audit log: append entries, verify the chain.")
    p.add_argument("--version", action="version", version=f"ProofLog {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    pi = sub.add_parser("init", help="create an empty log file")
    pi.add_argument("path")
    pi.add_argument("--force", action="store_true", help="reset an existing log")
    pi.set_defaults(func=_cmd_init)

    pa = sub.add_parser("append", help="append one entry to the log")
    pa.add_argument("path")
    pa.add_argument("--actor", required=True, help="who did it, e.g. officer.12")
    pa.add_argument("--action", required=True, help="what happened, e.g. permit.approved")
    pa.add_argument("--details", default=None, help="JSON object, e.g. '{\"id\": 42}'")
    pa.add_argument("--detail", action="append", default=[],
                    help="key=value detail (repeatable)")
    pa.add_argument("--key", default=None, help="HMAC key (prefer PROOFLOG_KEY env var)")
    pa.set_defaults(func=_cmd_append)

    pv = sub.add_parser("verify", help="verify the whole hash chain")
    pv.add_argument("path")
    pv.add_argument("--key", default=None)
    pv.set_defaults(func=_cmd_verify)

    ps = sub.add_parser("show", help="list entries in the log")
    ps.add_argument("path")
    ps.add_argument("--json", action="store_true", help="print raw JSON per entry")
    ps.set_defaults(func=_cmd_show)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
