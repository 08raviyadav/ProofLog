# Changelog

All notable changes to ProofLog are documented here.

## 0.1.0 — 2026-10-24

- Initial release.
- Single-file, zero-dependency audit log (`prooflog.py`): `init`, `append`,
  `verify`, `show` commands plus a Python API (`AuditLog`).
- SHA-256 hash chain over canonical JSON; verification names the first
  broken entry.
- Optional HMAC-SHA-256 key via `PROOFLOG_KEY` (or `--key`).
- 9 tests (stdlib `unittest`), including tamper, delete, and reorder cases.
