# ProofLog

**A tamper-evident audit log in one Python file. Zero dependencies.**

Public-service software makes decisions that affect real people — a permit
approved, a payment released, a record changed. When someone later asks
*"who did this, and was the record changed afterwards?"*, the honest answer
should not depend on trusting one database that anyone with write access can
quietly edit.

ProofLog chains every record to the one before it with a SHA-256 hash. Change,
delete, or reorder any entry, and verification fails — and tells you exactly
which entry broke first.

```
$ python prooflog.py init audit.jsonl
$ python prooflog.py append audit.jsonl --actor officer.12 \
      --action permit.approved --detail permit_id=P-1042
appended entry 0: officer.12 permit.approved (hash ca4e8ce7d92f...)

$ python prooflog.py verify audit.jsonl
PASS: OK: 1 entries, chain intact
```

Tamper with entry 0 afterwards, and verification says so plainly:

```
$ python prooflog.py verify audit.jsonl
FAIL: entry 0: hash mismatch — this entry was changed after it was written
```

## Install

No install step. Copy `prooflog.py` anywhere and run it with Python 3.9+:

```bash
python prooflog.py --help
```

Or use it as a library:

```python
from prooflog import AuditLog

log = AuditLog("audit.jsonl")
log.append(actor="officer.12", action="permit.approved",
           details={"permit_id": "P-1042"})
ok, message = log.verify()
assert ok, message
```

## Commands

| Command | What it does |
|---|---|
| `init <file>` | Create an empty log (`--force` resets an existing one) |
| `append <file> --actor X --action Y [--detail k=v]... [--details '{"k": v}']` | Add one entry |
| `verify <file>` | Check the whole chain; exit 0 if intact, 1 if broken |
| `show <file> [--json]` | List entries, human-readable or raw JSON |

## How it works

Each entry is one JSON line with `index`, `timestamp` (UTC), `actor`,
`action`, `details`, `prev_hash`, and `hash`. The hash covers every other
field, canonicalised (sorted keys, tight separators), so the same entry always
hashes the same way. Entry 0's `prev_hash` is 64 zeroes; every later entry's
`prev_hash` is the previous entry's `hash`. Verification recomputes every
hash and checks every link — the first mismatch is reported.

**Optional HMAC key.** Without a key, anyone holding the file could rewrite
the entire chain from scratch (and that is detectable only if you kept a copy
or a published hash elsewhere). With a key, the hash becomes HMAC-SHA-256, so
a rewritten chain will not verify without the key. Pass it via the
`PROOFLOG_KEY` environment variable — never `--key` on a shared machine, since
command lines end up in shell history. Verify with the same key.

## Honest limitations

- Tamper-**evident**, not tamper-**proof**. A hash chain proves a record was
  changed; it does not by itself stop a determined holder of the file from
  rewriting everything. For serious use, publish or archive log hashes
  somewhere the writer cannot rewrite.
- No signatures, no consensus, no blockchain. If you need non-repudiation
  (proving *who* signed an entry), add per-actor signing on top — that is on
  the roadmap, not in v0.1.
- One writer at a time. Concurrent appends from two processes can interleave;
  use a lock or a single writer service in production.
- JSONL grows forever. For very large logs, rotate files and keep the last
  hash of each file as the first link of the next.

## Tests

Standard library only — no pytest needed:

```bash
python -m unittest -v
```

9 tests, including the important negative ones: tampering with a middle entry,
the last entry, deleting an entry, and reordering entries must all fail
verification, and each failure names the broken entry.

## Roadmap

- Per-actor Ed25519 signatures (non-repudiation)
- Log rotation with hash carry-over
- A `verify --since <hash>` mode for checking only new entries
- A small read-only web viewer for published logs

## License

MIT — see [LICENSE](LICENSE). Built by Ravi Yadav.
