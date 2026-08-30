# Release candidate handoff — Technocore Capability Guard v0.1.0

## Current update — public CI and positioning

### Scope

This update changes only the public documentation, GitHub Actions configuration,
and repository-level static tests. The runtime under `src/`, route inventory,
package/CLI names, and `UPSTREAM_BASELINE.json` are unchanged.

The release candidate already contained a staged `.github/workflows/ci.yml`, so the
requested CI file was strengthened in place rather than added as a second workflow.
It now defines the six-job Ubuntu/Windows and Python 3.11/3.12/3.13 matrix, uses
read-only repository permissions, does not persist checkout credentials, installs
no packages, and runs each existing quality gate explicitly. The two actions use
the complete commit SHAs supplied by the human request.

README now uses the public product name **Technocore Capability Guard**, preserves
the `technocore_guard` package and `tc-guard` CLI names, distinguishes this offline
route-effect classifier from Technocore Link Guard, and states the official-status,
safety, upstream-authenticity, contribution, reward, airdrop, and eligibility
non-claims. It also separates CI checkout/Python provisioning from the runtime's
no-network guarantee.

### Test-first evidence

The CI policy test was added before changing the workflow. Against the prior
workflow it failed as intended:

```text
> python -m unittest discover -s tests -p test_project_safety.py -v
test_public_ci_is_pinned_least_privilege_and_install_free ... FAIL
AssertionError: 'name: CI\n' not found in 'name: ci\n...'
Ran 12 tests in 0.014s
FAILED (failures=1)
```

After the workflow update and final strengthening of the test:

```text
> python -m unittest discover -s tests -p test_project_safety.py -k public_ci -v
test_public_ci_is_pinned_least_privilege_and_install_free ... ok
Ran 1 test in 0.001s
OK
```

The static test allowlists exactly two pinned actions and exactly six run commands,
requires the single top-level `contents: read` permission block and
`persist-credentials: false`, and rejects secret references, write permissions,
dangerous workflow triggers, package installation, download commands, artifact
upload, and release creation patterns.

### Verification evidence before independent review

All commands ran from the repository root without network access:

```text
> python scripts/preflight.py
PREFLIGHT OK: secret-free project boundary
exit 0
```

```text
> python -m unittest discover -s tests -v
Ran 83 tests in 4.882s
OK
exit 0
```

```text
> python -m compileall -q src tests scripts
exit 0; no output
```

```text
> python scripts/security_lint.py
SECURITY LINT OK: 6 runtime Python files, 50 reviewable project files, commands=['inspect', 'verify-ledger']
exit 0
```

```text
> python scripts/build_release_manifest.py --check-only
MANIFEST CHECK OK: 46 files, version=0.1.0, sha256=5d8d231c6e8263651dcc24d0618ab16c8c98107ad825844f285b7ddaf200e9c8
exit 0
```

```text
> PowerShell -ExecutionPolicy Bypass -File .\scripts\quality.ps1
PREFLIGHT OK: secret-free project boundary
Ran 83 tests in 4.816s
OK
SECURITY LINT OK: 6 runtime Python files, 50 reviewable project files, commands=['inspect', 'verify-ledger']
MANIFEST CHECK OK: 46 files, version=0.1.0, sha256=5d8d231c6e8263651dcc24d0618ab16c8c98107ad825844f285b7ddaf200e9c8
exit 0
```

```text
> git diff --check
exit 0; no output

> git diff --cached --check
exit 0; no output (pre-refreeze index)
```

### Current limitations and release blockers

- The workflow has not run on GitHub. YAML and security properties were inspected
  statically, but a green public matrix requires a later human-controlled commit
  and push.
- The action SHAs and version annotations came from the human request and were not
  checked against GitHub because network access is prohibited.
- No tag, release asset, upstream Issue, or DID anchor can exist before the human
  creates the reviewed commit and observes green CI.
- The pinned route baseline, ledger checkpoint limitation, and lack of concurrent
  writer support remain unchanged.

### Explicit non-actions

No runtime code, CLI command, route inventory, baseline, BLOCKED/FUTURE feature, or
dependency was changed. No network, DNS, browser, GitHub, Technocore, package
installation, commit, tag, push, release, Issue, PR, signing, DID/key access,
starter access, wallet, Faucet, token, claim, or secret access occurred.

### Current review request

A fresh reviewer that did not implement this update must inspect the complete staged
snapshot, rerun the required gates and static CI test, try to refute the documentation
and workflow claims, and replace `review.md` with an explicit verdict. Only an
`approve` verdict permits the final staged tree to be written.

---

## Historical release-freeze record

The sections below preserve the independently reviewed pre-CI release-freeze record.
Their 82-test and prior-manifest values are historical, not the current final counts.

## Scope

This handoff covers a local, uncommitted release-candidate freeze. It does not claim that the tool is vulnerability-free, published, accepted upstream, or safe for any effectful operation. Runtime route policy and `UPSTREAM_BASELINE.json` were not changed.

The workspace root and its resolved path matched, the root was neither link-like nor a Windows reparse point, and a new regular in-project `.git` directory was initialized on branch `main`. No parent repository was queried and no global Git configuration was changed.

## Release-freeze changes

- Added deterministic LF attributes and defense-in-depth ignore rules for caches, build output, local evidence, temporary files, and credential-shaped paths.
- Added a concise `CHANGELOG.md` entry for 0.1.0 without inventing prior history.
- Documented the public CLI surface, authoritative version metadata, fixed human-reviewed upstream baseline, and ledger checkpoint/concurrency limits.
- Made check-only release-manifest construction deterministic in an unborn in-project repository while continuing to require a clean committed `HEAD` for writable release evidence.
- Excluded local Codex cache/session state, generated artifacts, and process evidence (`handoff.md` and `review.md`) from release-manifest inputs.
- Changed the repository path-safety test to prune excluded directories instead of traversing `.git`.
- Added regression tests for release configuration, documentation, version consistency, process-evidence exclusion, and unborn-Git manifest behavior.

## Test-first evidence

Before `CHANGELOG.md` and the README release-boundary text were added, the new documentation test failed with:

```text
FileNotFoundError: [Errno 2] No such file or directory: '.../CHANGELOG.md'
Ran 11 tests
FAILED (errors=1)
```

Before the implementation changes, targeted tests also rejected the missing `.gitattributes`, missing release exclusions, and check-only handling of an unborn local repository. Those tests pass in the final suite below.

## Verification evidence

All commands were run from the repository root with network access unused. Git commands used process-local configuration isolation and did not read or modify global Git configuration.

```text
> python scripts/preflight.py
PREFLIGHT OK: secret-free project boundary
```

```text
> python -m unittest discover -s tests -v
Ran 82 tests in 2.530s
OK
```

```text
> python -m compileall -q src tests scripts
exit 0; no output
```

```text
> python scripts/security_lint.py
SECURITY LINT OK: 6 runtime Python files, 50 reviewable project files, commands=['inspect', 'verify-ledger']
```

```text
> python scripts/build_release_manifest.py --check-only
MANIFEST CHECK OK: 46 files, version=0.1.0, sha256=8bbabd34d69371bbefb8bba175dc083ab0397ea90cfe994337857344020b52c8
```

The manifest check was repeated without source changes and produced the same file count and digest.

```text
> PowerShell -ExecutionPolicy Bypass -File .\scripts\quality.ps1
PREFLIGHT OK: secret-free project boundary
Ran 82 tests in 2.413s
OK
SECURITY LINT OK: 6 runtime Python files, 50 reviewable project files, commands=['inspect', 'verify-ledger']
MANIFEST CHECK OK: 46 files, version=0.1.0, sha256=8bbabd34d69371bbefb8bba175dc083ab0397ea90cfe994337857344020b52c8
exit 0
```

```text
> git diff --check
exit 0; no output
```

CLI help exited 0 for the root parser, `inspect`, and `verify-ledger`. The root usage listed exactly `{inspect,verify-ledger}` and stated that the classifier never fetches the URL. `--version` is not implemented and was not added.

## Known limits

- The fixed upstream baseline can drift; updates require a separate human-reviewed task.
- The ledger is tamper-evident, not tamper-proof. Tail removal or a fully recomputed chain requires a trusted external checkpoint to detect.
- Concurrent ledger writers remain outside the v0.1.0 scope.
- A manifest suitable for publication cannot be generated until a human creates and reviews a clean commit; this task performs check-only construction and must not commit.
- Classification is a pinned-policy effect estimate, not a proof of upstream honesty, identity, or eligibility.

## Explicit non-actions

No network access, URL opening, DNS resolution, Technocore read/write, GitHub access/publication, package installation, signing, DID/key handling, Faucet/wallet/token/claim operation, commit, tag, or push was performed. The external participation starter and all secret material were not read.

## Review request

A fresh reviewer must inspect the complete staged source snapshot, rerun the required gates, try to refute the claims above, and write `review.md`. Only an explicit `approve` verdict permits creation of the uncommitted Git tree object.
