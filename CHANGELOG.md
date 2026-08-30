# Changelog

## 0.1.0

Initial offline release candidate:

- classifies reviewed Technocore URL shapes without network or DNS access;
- fails closed for malformed, ambiguous, disguised, or unknown inputs;
- redacts capability names and user-controlled write material from reports and the optional ledger;
- records optional tamper-evident local evidence without retaining the raw URL or its deterministic hash;
- verifies ledger chain integrity while documenting checkpoint, tail-truncation, full-recomputation, and concurrent-writer limits;
- uses only the Python standard library and exposes only `inspect` and `verify-ledger`.
