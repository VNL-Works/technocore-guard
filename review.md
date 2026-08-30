# Independent release-candidate review — Technocore Capability Guard v0.1.0

## Scope and independence

This review was performed on 2026-08-30 from a fresh context that did not
implement this release candidate. I read the mandated repository contract,
baseline, product specification, threat model, architecture, implementation
plan, differentiation document, handoff, prior review, security policy, README,
workflow, project-safety tests, and the complete staged diff. I then tried to
refute the handoff's CI, positioning, offline-runtime, route-policy, and
redaction claims.

No network, DNS, browser, external repository, package installation, credential
or secret access, external-starter access, commit, tag, push, release, issue,
PR, Git tree write, or runtime outbound action was performed. Per the review
request, the only working-tree file changed by this reviewer is `review.md`; it
is intentionally not staged.

## Staged-snapshot evidence

The local repository is an unborn `main` repository. At inspection time the
index contained 50 staged additions, and the complete staged diff was 4,833
insertions across source, policy, documentation, configuration, scripts, and
tests. `git diff --cached --name-status` showed the expected public project
files only. The staged baseline and route inventory are internally consistent:
both pin commit `aa7017feba970337324e972f329f7382da838e01`, and the policy
inventory test asserts the exact reviewed read and write lists. No runtime
dependency is declared; the only CLI entry point is `tc-guard`.

The prior staged `review.md` was historical review evidence. This replacement
records the current, independent review without adding a staging operation.

## Required verification

```text
> python scripts/preflight.py
PREFLIGHT OK: secret-free project boundary

> python -m unittest discover -s tests -v
Ran 83 tests in 1.352s
OK

> python -m compileall -q src tests scripts
exit 0; no output

> python scripts/security_lint.py
SECURITY LINT OK: 6 runtime Python files, 50 reviewable project files, commands=['inspect', 'verify-ledger']

> python scripts/build_release_manifest.py --check-only
MANIFEST CHECK OK: 46 files, version=0.1.0, sha256=eb6be1f68b67d1649a06fab0a9a0d9dfab5207b23e37961373ffedda5ff81a73

> PowerShell -ExecutionPolicy Bypass -File .\scripts\quality.ps1
PREFLIGHT OK: secret-free project boundary
Ran 83 tests in 1.380s
OK
SECURITY LINT OK: 6 runtime Python files, 50 reviewable project files, commands=['inspect', 'verify-ledger']
MANIFEST CHECK OK: 46 files, version=0.1.0, sha256=eb6be1f68b67d1649a06fab0a9a0d9dfab5207b23e37961373ffedda5ff81a73
exit 0

> git diff --check
exit 0; no output

> git diff --cached --check
exit 0; no output

> python -m unittest discover -s tests -p test_project_safety.py -k public_ci -v
test_public_ci_is_pinned_least_privilege_and_install_free ... ok
Ran 1 test in 0.001s
OK
```

## Adversarial review and findings

- **Workflow: no blocking finding.** `.github/workflows/ci.yml` has only
  `push` to `main`, `pull_request`, and manual-dispatch triggers; one top-level
  `permissions: contents: read` block; checkout credential persistence disabled;
  a bounded 15-minute Ubuntu/Windows × Python 3.11/3.12/3.13 matrix; and
  fail-fast disabled. The only actions are the reviewed full-SHA pins for
  `actions/checkout` and `actions/setup-python`. Its six explicit run steps are
  the preflight, unit tests, compilation, security lint, check-only manifest,
  and whitespace check. It has no secret reference, write permission,
  pull-request-target/workflow-run trigger, install/download command, artifact
  upload, release action, or release command. Action-SHA provenance was not
  independently verified because network access is prohibited.
- **Offline and policy boundary: no blocking finding.** The full runtime source
  diff has no networking, DNS, browser, dynamic-import, subprocess, credential
  environment, or outbound CLI path. The static security linter and adversarial
  tests confirm exactly `inspect` and `verify-ledger`; GET/HEAD write shapes
  remain critical writes; wrong methods and unknown official routes fail closed;
  and serialization/ledger records use a fixed redacted schema. The pinned
  baseline and exact route inventory agree, so the release candidate does not
  imply a route-policy or baseline expansion.
- **Positioning and non-claims: no blocking finding.** README correctly names
  the product while retaining `technocore_guard` and `tc-guard`, distinguishes
  it from Technocore Link Guard, states it is not official, and avoids safety,
  authenticity, contribution, reward, airdrop, and eligibility guarantees. It
  explicitly separates CI checkout/Python provisioning from the runtime's
  no-network guarantee, which matches the workflow and source.
- **Handoff refutation attempt: no blocking finding.** Fresh validation produced
  83 passing tests rather than relying on the handoff's earlier output. The
  fresh manifest digest differs from historical handoff/pre-review values, as
  expected because the staged source snapshot now includes the CI/positioning
  update; the current check-only command is deterministic within this review
  (the quality gate reproduced the same digest). No test was disabled or marked
  expected.

**Blocker/high/medium/low findings: none.**

## Known limitations

- GitHub Actions has not run remotely; this is a static workflow review only.
- The action pins and upstream baseline are not proof of current upstream state;
  network verification is intentionally outside this offline review.
- The fixed policy can drift, and the classifier only reports likely effects
  under that human-reviewed policy.
- The ledger remains tamper-evident rather than tamper-proof: tail truncation or
  full recomputation requires a trusted external checkpoint to detect; concurrent
  writers are out of scope.
- A publishable manifest still requires a human-reviewed clean commit. No commit,
  tag, publication, release artifact, or DID anchor was created.

## Final verdict

approve
