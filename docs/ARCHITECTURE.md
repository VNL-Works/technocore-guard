# Architecture

## `classifier.py`

Pure function from `(raw_url, method)` to `Inspection`:

1. reject unsupported methods and invisible/raw ambiguity;
2. parse absolute URL;
3. enforce lowercase `https://` and the exact canonical authority spelling;
4. reject encoded controls and routing delimiters;
5. reject decoded invisible characters, second-pass decoding changes, and dot segments;
6. match the reviewed route shape;
7. review query keys without echoing unknown names or values; warnings on a
   read-shaped route make the result unknown, while a known write shape stays a write;
8. return a redacted object.

No runtime function resolves a hostname or opens a socket.

## `models.py`

Typed effect, risk, and redacted inspection model. `to_public_dict()` is the supported
serialisation boundary. It builds an explicit field allowlist and validates route IDs,
fixed reasons, placeholder-only targets, methods, flags, and warnings before returning
data. Caller-constructed free text is not serialisable through this boundary.

## `ledger.py`

Optional local JSONL chain. Every record contains a sequential number, previous-record hash, hash of the redacted event, and record hash over canonical JSON. It never receives the raw URL or a deterministic hash of it. Appends rewrite through an atomic temporary file. Concurrent writers are out of scope for v0.1.0.

Verification rejects duplicate JSON keys, non-finite JSON values, extra record/event
fields, non-canonical timestamps, malformed hashes, and non-integer sequences. A
corrupt chain is verified before append and is never rewritten. Credential-shaped and
link-like ledger paths are rejected before filesystem reads or writes. Link-like
includes Windows reparse points through an `lstat` fallback compatible with Python
3.11. Atomic replacement retries only bounded Windows sharing/lock violations; other
I/O failures remain fail-closed.

## `cli.py`

Only:

- `inspect`
- `verify-ledger`

The absence of `fetch`, `write`, `sign`, and `commit` is tested.
Parser errors use fixed text rather than echoing untrusted argument values. Standard
input mode accepts exactly one line and is bounded before classification.

## Why this is not a proxy

A proxy must accept an untrusted destination and then make a request. Even an allowlisted proxy creates redirect, DNS, response-injection, credential, timeout, and method-confusion surfaces. v0.1.0 produces a decision artifact only.

## Policy updates

`UPSTREAM_BASELINE.json` pins the reviewed source revision and does not auto-update. A human must retrieve and review official changes, update baseline and route inventory together, and add tests before behavior broadens.
