from __future__ import annotations

import os
from pathlib import Path

try:
    from .project_safety import forbidden_path_reason, is_link_like, is_scan_excluded
except ImportError:  # Direct script execution.
    from project_safety import forbidden_path_reason, is_link_like, is_scan_excluded

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (ROOT / "AGENTS.md", ROOT / "pyproject.toml", ROOT / "UPSTREAM_BASELINE.json")
BLOCKED_EXACT_ENV = {"SIGN_SEED"}
BLOCKED_PREFIXES = ("TECHNOCORE_", "FLOP_", "WALLET_", "MNEMONIC_")
WARN_EXACT_ENV = {"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GITHUB_TOKEN", "GH_TOKEN"}
WARN_PREFIXES = ("AWS_", "AZURE_", "GOOGLE_")


def fail(message: str) -> None:
    raise SystemExit(f"PREFLIGHT FAILED: {message}")


def main() -> None:
    for path in REQUIRED:
        if not path.is_file():
            fail(f"required file is missing: {path.relative_to(ROOT)}")

    if "flop-technocore-starter" in {part.lower() for part in ROOT.parts}:
        fail("the guard repository must not be nested inside the participation starter")

    for current, dirnames, filenames in os.walk(ROOT, followlinks=False):
        current_path = Path(current)
        kept_directories: list[str] = []
        for name in dirnames:
            candidate = current_path / name
            relative = candidate.relative_to(ROOT)
            reason = forbidden_path_reason(relative)
            if reason:
                fail(f"{reason} found inside the project")
            if is_link_like(candidate):
                fail("link-like entries are not allowed in the reviewable workspace")
            if not is_scan_excluded(relative):
                kept_directories.append(name)
        dirnames[:] = kept_directories
        for name in filenames:
            candidate = current_path / name
            relative = candidate.relative_to(ROOT)
            reason = forbidden_path_reason(relative)
            if reason:
                fail(f"{reason} found inside the project")
            if is_link_like(candidate):
                fail("link-like entries are not allowed in the reviewable workspace")

    blocked_names = sorted(
        name
        for name in os.environ
        if name in BLOCKED_EXACT_ENV or name.startswith(BLOCKED_PREFIXES)
    )
    if blocked_names:
        fail("identity-related environment variables are visible")

    warning_names = sorted(
        name for name in os.environ if name in WARN_EXACT_ENV or name.startswith(WARN_PREFIXES)
    )
    if warning_names:
        print(
            "PREFLIGHT WARNING: unrelated credential-like environment variable names are visible; "
            f"Codex config is expected to filter them ({len(warning_names)} name(s))"
        )

    print("PREFLIGHT OK: secret-free project boundary")


if __name__ == "__main__":
    main()
