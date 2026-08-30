# Technocore Capability Guard

**Offline, fail-closed effect classifier and tamper-evident local ledger for technocore.chat URLs.**

Technocore URLs can be capabilities, not ordinary links. Technocore exposes some write operations through HTTP `GET` paths. An AI agent that merely “checks” an untrusted URL can therefore append a public message or replace a note. Technocore Capability Guard classifies the likely effect **without opening the URL**.

Technocore Capability Guard v0.1.0 exposes only the `inspect` and `verify-ledger` commands. Neither command opens a URL, resolves a host, or sends a request. The Python package remains `technocore_guard`, and the installed CLI remains `tc-guard`.

## What v0.1.0 does

- distinguishes reviewed read routes from GET-shaped and POST-shaped writes;
- rejects non-official or noncanonical-case authorities, userinfo tricks, ports, even empty fragments, raw whitespace, encoded controls/routing delimiters, double encoding, and dot segments;
- treats unreviewed query semantics on a read-shaped route as unknown, while never downgrading a known write shape;
- marks unlisted `p-` rooms, namespaces, and keys as capabilities and never prints their names;
- never stores the raw URL, a deterministic hash of private input, message text, note values, signatures, or nonces;
- optionally records redacted results in a tamper-evident local JSONL chain;
- rejects malformed, duplicate-key, schema-expanded, credential-path, symlink, junction, and other reparse-point ledger data before append;
- uses only the Python standard library;
- performs no network, DNS, signing, wallet, Faucet, or token operation.

## Relationship to other tools

Technocore Capability Guard accepts a `technocore.chat` URL string and classifies its likely `read`, `write`, `unknown`, or `blocked` effect entirely offline. It does not fetch or execute the URL.

[Technocore Link Guard](https://github.com/devorun/technocore-link-guard) is a separate project that reads public rooms and evaluates risk signals in external links. This project is neither a fork nor a replacement for Technocore Link Guard. The two tools are complementary: their inputs, threat models, and network boundaries differ.

## Security boundary and non-claims

Technocore Capability Guard is an independent project, not an official Technocore tool. A `read` or otherwise clean-looking classification is not a safety guarantee; it is only a likely effect under the pinned, human-reviewed route policy. The result does not prove that upstream is authentic, honest, current, or implemented as classified. It also does not prove a contribution, reward, airdrop, or eligibility claim.

The runtime implements no network access. Public CI infrastructure checks out the repository and provisions the selected Python version; that infrastructure activity is a separate layer from the runtime no-network guarantee. The validation steps install no package or external dependency, and they do not make the classifier connect to a remote service.

## The deliberate separation

Keep this repository in its own folder and open **only this folder** in Codex.

```text
parent/
├─ flop-technocore-starter/  # private identity vault; already joined
└─ technocore-guard/         # public contribution repository; no secrets
```

Do not place the guard repository inside the starter repository. Do not copy `.secrets` or `.agent` into it.

## Try it locally

Python 3.11 or later is enough. No package download is required.

```powershell
$env:PYTHONPATH = "src"
python -m technocore_guard inspect "https://technocore.chat/llms.txt"
python -m technocore_guard inspect "https://technocore.chat/r/lobby/say/example/hello"
```

For a real private capability, avoid putting the URL in shell history or a process argument. Feed exactly one line on standard input instead:

```powershell
Get-Clipboard | python -m technocore_guard inspect -
```

A write-shaped URL produces a redacted report similar to:

```json
{
  "effect": "write",
  "network_executed": false,
  "risk": "critical",
  "route_id": "unsigned-room-write",
  "sanitized_target": "/r/<room>/say/<nick>/<text>"
}
```

Record only the redacted result:

```powershell
python -m technocore_guard inspect `
  "https://technocore.chat/r/lobby/say/example/hello" `
  --record evidence/local-ledger.jsonl

python -m technocore_guard verify-ledger evidence/local-ledger.jsonl
```

The raw URL is not represented at all—not even by a deterministic public hash. This avoids turning a low-entropy capability or private value into a dictionary-testable commitment.

### Ledger security boundary

The ledger is tamper-evident, not tamper-proof. Verification detects changes within the presented chain, but a trusted external checkpoint is needed to detect removal of the tail or replacement with an entirely recomputed chain. Concurrent writers are outside the v0.1.0 scope; serialize writes in a single process.

### Frozen policy and version metadata

The upstream baseline is a human-reviewed fixed snapshot; this tool never updates it automatically. A changed upstream route remains unknown until a separate human-reviewed policy update.

`[project].version` in `pyproject.toml` is authoritative. The package-level version mirror is covered by a consistency test so release metadata cannot silently drift.

## Give Codex the safe implementation task

1. Extract this project into a directory separate from the participation starter.
2. Open only `technocore-guard` in Codex.
3. Start Codex using `scripts/start-codex-safe.ps1`, or verify permissions are workspace-only with network disabled.
4. Paste the contents of `CODEX_IMPLEMENTATION_PROMPT.md`.
5. Review the diff and validation report before committing anything.

Codex's local sandbox and approval policy are a second line of defense. The first line is architectural: v0.1.0 has no runtime code path that can send a request.

## Contribution evidence

Git history and GitHub Releases are the durable source of truth. A Technocore message is only an optional public anchor.

After a release is reviewed:

```powershell
python scripts/build_release_manifest.py
python scripts/render_release_anchor.py `
  --version 0.1.0 `
  --repository "https://github.com/OWNER/technocore-guard"
```

The second command prints a one-line draft; it does not send it. Publish it through the existing starter only after manually verifying the exact text and explicitly approving one signed write. See `docs/PUBLISH_WITH_EXISTING_DID.md`.

## Non-goals

Technocore Capability Guard does not verify that an announcement is true, identify official personnel, provide Sybil resistance, guarantee airdrop eligibility, connect a wallet, request testnet tokens, or automatically follow any URL returned by Technocore.
