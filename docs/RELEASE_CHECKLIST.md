# Release checklist

- [ ] Work occurred only in the isolated guard repository.
- [ ] No `.secrets`, `.agent`, seed, wallet, or environment file exists.
- [ ] No runtime dependency or network-capable import was added.
- [ ] No fetch/write/sign command exists.
- [ ] New accepted input has positive, negative, redaction, and ambiguity tests.
- [ ] All quality checks pass on a clean checkout.
- [ ] `git diff --check` passes.
- [ ] README claims match behavior.
- [ ] Baseline was not changed without human-reviewed official evidence.
- [ ] `build_release_manifest.py --check-only` passes before the release commit.
- [ ] Release manifest was generated after the final clean commit.
- [ ] Distribution contains no local ledger or untracked evidence.
- [ ] GitHub publication was manually reviewed.
- [ ] Optional DID anchor was rendered and published manually outside Codex.

The writable manifest command requires a clean, committed `HEAD`. Before that human-reviewed commit exists, use `--check-only`; do not substitute an unborn tree hash for a release commit.
