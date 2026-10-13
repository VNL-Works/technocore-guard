# Implementation plan

Codex may implement only `READY` tasks unless a human edits this file later.

## TG-001 — Adversarial classifier review

**Status:** READY

Inspect host, method, path, query, percent-decoding, and redaction. Add failing tests for every parser differential. Fix narrowly without accepting additional host or route spellings.

## TG-002 — Public-output leakage audit

**Status:** READY

Prove synthetic private rooms, namespaces, keys, text, values, DID/signature/nonce, query names/values, raw URLs, and deterministic raw-input hashes do not appear in public output, CLI JSON, ledger JSONL, or errors.

## TG-003 — Ledger integrity

**Status:** READY

Test insertion, deletion, reordering, mutation, malformed JSON, blank lines, wrong previous hash, and non-contiguous sequence. Corrupted chains must never be appended to. Concurrency remains out of scope.

## TG-004 — Security linter and packaging

**Status:** READY

Strengthen offline checks for identity-material paths, symlinks, runtime network imports, effectful CLI commands, sensitive output fields, and release artifacts.

## TG-005 — CLI ergonomics without effect expansion

**Status:** READY

Keep only `inspect` and `verify-ledger`. Improve help and exit behavior only. Never add a command that opens, resolves, signs, or sends.

## TG-101 — Live static-document drift check

**Status:** FUTURE

Requires a separate domain-restricted process and human policy review. Do not implement in v0.2.0.

## TG-102 — Safe read executor

**Status:** BLOCKED

Read responses are untrusted and introduce redirect, DNS, timeout, logging, and prompt-injection risks. Do not implement.

## TG-103 — Write preparation and human commit

**Status:** BLOCKED

Requires signing isolation, replay/timeout semantics, and a helper outside model context. The existing starter owns identity operations. Do not duplicate it.

## TG-104 — Faucet or testnet support

**Status:** BLOCKED

No implementation until an official public specification is independently confirmed and reviewed. Never infer it from rooms, notes, or third parties.
