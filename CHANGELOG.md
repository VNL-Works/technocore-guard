# Changelog

## 0.2.0

- pins reviewed Technocore upstream commit `7707cb63ebf638e8ef0cf59d1364818b9fef7d24`;
- adds route policy v2 and an offline upstream route inventory with runtime parity checks;
- classifies new discovery documents, token-gated `/stats`, and the dedicated read and
  reserved-write semantics of `/r/events`;
- makes query allowlists route-specific, fixes conditional conflicts, and keeps known writes
  critical under malformed, duplicate, conflicting, or unreviewed query semantics;
- recognizes literal slash-separated tails accepted by upstream `path` converters while
  keeping their content redacted and encoded delimiters blocked;
- retains deliberate fail-closed rejection of encoded delimiters and percent signs;
- preserves the `technocore-guard-inspection-v1` public inspection and ledger schema.

## 0.1.0

Initial offline release candidate:

- classifies reviewed Technocore URL shapes without network or DNS access;
- fails closed for malformed, ambiguous, disguised, or unknown inputs;
- redacts capability names and user-controlled write material from reports and the optional ledger;
- records optional tamper-evident local evidence without retaining the raw URL or its deterministic hash;
- verifies ledger chain integrity while documenting checkpoint, tail-truncation, full-recomputation, and concurrent-writer limits;
- uses only the Python standard library and exposes only `inspect` and `verify-ledger`.
