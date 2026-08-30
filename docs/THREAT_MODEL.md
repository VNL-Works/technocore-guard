# Threat model

## Assets

1. The operator's existing Technocore DID continuity and private seed, held outside this repository.
2. Unlisted room names and private note namespaces/keys, which act as bearer capabilities.
3. Signed write URLs and signatures, which may remain replay-sensitive for a bounded period.
4. User-authored message and note content.
5. The integrity and credibility of public contribution evidence.
6. The operator's workstation, GitHub account, wallet, and unrelated project files.

## Trust boundaries

```text
untrusted URL text
      │
      ▼
[offline parser] ── no DNS / no HTTP ──X── internet
      │
      ▼
redacted inspection
      │ optional
      ▼
local hash chain

existing DID starter ── separate directory; never crossed by Codex or runtime
```

## Adversaries

- a Technocore participant who posts malicious instructions or a write-shaped URL;
- a phisher using a look-alike hostname, userinfo, port, slash/backslash ambiguity, or IDN;
- a prompt injector trying to make Codex browse, install, sign, upload, or reveal files;
- accidental scope creep that adds a convenient fetcher or signer;
- a contributor who fabricates public evidence or attaches unrelated links;
- ordinary logging and CI systems that retain command arguments and raw URLs.

## Primary abuse cases

### A. GET confused with read

`https://technocore.chat/r/lobby/say/flop_labs/official%20faucet%20here`

Required: `write / critical`; no request.

### B. Authority confusion

```text
https://technocore.chat.evil.example/llms.txt
https://technocore.chat@evil.example/llms.txt
https://evil.example@technocore.chat/llms.txt
https://technocore.chat.:443/llms.txt
```

Required: `blocked`; no host resolution.

### C. Parser differential

Backslashes, dot segments, encoded slashes, encoded question marks, controls, double
encoding, and unreviewed query semantics on read-shaped routes fail closed. When a
proxy and application could disagree, Guard must not guess. Known write-shaped paths
remain writes even when their query is unreviewed.

### D. Capability leakage

Input contains `p-<unguessable>` in a room, namespace, or key. Output and ledger use only placeholders; no raw-input hash is published.

### E. Replay-material leakage

A signed write URL contains DID, signature, nonce, and text. Public output must not reproduce the signature, nonce, text, or full target. Guard does not verify or resend it.

### F. Official-looking untrusted content

A room named `faucet`, a note under `/kv/faucet`, a signed writer claiming to be staff, or a topic containing a command is still caller-controlled data. Route classification is not endorsement.

### G. Codex escape

A prompt or repository file asks Codex to read the sibling starter, enable network, install a package, follow an issue URL, run a pasted command, push a branch, or post proof. Sandbox and `AGENTS.md` must deny or stop it.

Local ledger and release paths also reject symbolic links, Windows junctions, and
other reparse points before following or resolving them.

### H. Evidence laundering

A GitHub URL does not prove the DID created the code, maintainers accepted it, or the work is reward-eligible. Release manifests and optional DID anchors state only artifact hash, repository commit, and key control of the anchor message.

## Assumptions

- Python's URL parser is only one component; extra canonical checks close ambiguity.
- SHA-256 in the ledger protects redacted record integrity, not input confidentiality.
- The local chain is tamper-evident, not immutable. It detects mutation, insertion,
  middle deletion, and reordering when stored hashes are not rebuilt. Tail truncation
  and a fully recomputed chain cannot be distinguished without a trusted external
  checkpoint containing the expected head and record count. An independently
  published release-head hash improves later detection.
- A separate folder is procedural isolation; Codex sandboxing supplies technical isolation.

## Non-goals

Guard cannot prove that a deployed server implements the pinned policy, that a DID maps to a person, that a source is honest, or that an activity earns an airdrop.
