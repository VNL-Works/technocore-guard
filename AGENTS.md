# Codex operating contract — mandatory

This repository is a **public, secret-free development workspace** for an offline safety tool. It is deliberately separate from the existing `flop-technocore-starter`, which holds the operator's persistent Technocore DID and private seed.

These instructions apply to every coding agent in this repository.

## 1. Read order

Before changing anything, read these files in order:

1. `AGENTS.md`
2. `UPSTREAM_BASELINE.json`
3. `docs/PRODUCT_SPEC.md`
4. `docs/THREAT_MODEL.md`
5. `docs/ARCHITECTURE.md`
6. `tasks/IMPLEMENTATION_PLAN.md`
7. `docs/DIFFERENTIATION.md`

## 2. Hard boundaries

- Work only inside this repository. Do not inspect parent, sibling, home, Downloads, cloud-sync, or other project directories.
- Never search for, open, print, copy, hash, move, or modify `.secrets/`, `.agent/`, `ed25519_seed.hex`, wallet files, mnemonics, API keys, tokens, browser profiles, SSH keys, or credential stores.
- The existing participation starter is an **external identity vault**, not a dependency. Do not import it, link to its private files, or invoke its signing commands.
- No network access is needed or permitted for v0.1.0. Do not browse, `curl`, `Invoke-WebRequest`, clone, pull, install packages, call GitHub, call Technocore, resolve DNS, or open URLs.
- Do not add runtime imports or dependencies that can perform network I/O.
- Do not create `fetch`, `safe-read`, `say`, `write`, `commit-write`, `sign`, `faucet`, `wallet`, `claim`, or token-related commands.
- Do not implement a generic proxy. A proxy would turn untrusted input into outbound actions and invert the safety model.
- Do not create or regenerate a DID. This repository contains no identity key by design.
- Do not run `git push`, open an Issue or PR, publish a release, post to X, submit a form, or write to Technocore without a separate explicit human instruction.

When a requested change conflicts with a hard boundary, stop and report the conflict. Do not weaken the boundary to make the task easier.

## 3. v0.1.0 product invariant

`tc-guard` is a **pure offline classifier**:

```text
untrusted URL string
        ↓
strict parse + fail-closed route policy
        ↓
redacted effect report
        ↓ optional
local hash-chained evidence ledger
```

For all normal and error paths:

- no network request occurs;
- no DNS lookup occurs;
- no subprocess is needed at runtime;
- the raw URL or a deterministic hash of it is not stored in the result or ledger;
- room capability names, note locations, message text, values, signatures, and nonces are redacted;
- unknown official-origin routes are not assumed safe;
- GET-shaped write routes are classified as writes;
- malformed, disguised, or ambiguous authorities fail closed.

## 4. Implementation discipline

- Python standard library only for runtime and tests.
- Write or update a failing test before changing security-sensitive behavior.
- Prefer explicit code over clever normalization. URL parsers, reverse proxies, and frameworks disagree at the edges; ambiguity must be blocked, not guessed through.
- Every new route classification requires a policy entry, positive tests, wrong-method tests, redaction tests, adversarial encoding tests, and a human-reviewed official baseline update.
- Never silently widen accepted host spellings, schemes, ports, redirects, path encodings, methods, or query parameters.
- Never place the raw URL in exceptions, assertion messages, logs, snapshots, fixtures intended for publication, or evidence files.
- Keep output claims narrow: classification shows the likely HTTP effect under the pinned policy. It does not prove an endpoint is honest, current, official beyond the exact origin, or eligible for an airdrop.

## 5. Required validation

```text
python -m unittest discover -s tests -v
python -m compileall -q src tests scripts
python scripts/security_lint.py
python scripts/build_release_manifest.py --check-only
```

On Windows:

```powershell
PowerShell -ExecutionPolicy Bypass -File .\scripts\quality.ps1
```

All checks must pass. Do not disable tests, loosen assertions, or mark failures as expected without explaining the root cause.

## 6. Change report

At the end of a Codex session, report files changed, tests added or changed, exact validation commands and results, remaining ambiguities, and every action intentionally not performed because it would require network, secrets, publication, or an upstream decision.

Do not claim a contribution was submitted or accepted unless a human actually completed that action and supplied its public evidence.
