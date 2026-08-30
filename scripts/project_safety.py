from __future__ import annotations

import os
from pathlib import Path


FORBIDDEN_PARTS = {".secrets", ".agent", ".ssh", ".aws"}
FORBIDDEN_EXACT_NAMES = {
    ".npmrc",
    ".netrc",
    "auth.json",
    "credentials",
    "credentials.json",
    "ed25519_seed.hex",
}
FORBIDDEN_NAME_FRAGMENTS = {
    "api-key",
    "api_key",
    "apikey",
    "client_secret",
    "mnemonic",
    "private-key",
    "private_key",
    "seed",
    "seed_phrase",
    "token",
    "wallet",
}
FORBIDDEN_KEY_SUFFIXES = {".key", ".p12", ".pem", ".pfx", ".seed"}

SCAN_EXCLUDED_PARTS = {
    ".git",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tc-guard",
    "build",
}
RELEASE_EXCLUDED_PARTS = SCAN_EXCLUDED_PARTS | {"dist", "evidence"}
RELEASE_EXCLUDED_EXACT_PATHS = {("handoff.md",), ("review.md",)}


def _lower_parts(path: Path) -> tuple[str, ...]:
    return tuple(part.lower() for part in path.parts)


def forbidden_path_reason(path: Path) -> str | None:
    """Classify path names only; never open or resolve the candidate."""

    parts = _lower_parts(path)
    if set(parts) & FORBIDDEN_PARTS:
        return "identity or credential directory"
    pairs = set(zip(parts, parts[1:]))
    if (
        (".codex", "auth.json") in pairs
        or (".claude", ".credentials.json") in pairs
        or (".config", "gh") in pairs
    ):
        return "credential store path"
    for name in parts:
        if name == ".env" or name.startswith(".env."):
            return "environment credential file"
        if name in FORBIDDEN_EXACT_NAMES:
            return "credential file"
        if name.startswith(("id_dsa", "id_ecdsa", "id_ed25519", "id_rsa")):
            return "private-key-like file"
        if any(fragment in name for fragment in FORBIDDEN_NAME_FRAGMENTS):
            return "identity or credential-like file"
        if name.endswith(tuple(FORBIDDEN_KEY_SUFFIXES)):
            return "private-key-like file"
    return None


def is_link_like(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        attributes = getattr(os.lstat(path), "st_file_attributes", 0)
        if attributes & 0x0400:  # Windows FILE_ATTRIBUTE_REPARSE_POINT.
            return True
        is_junction = getattr(path, "is_junction", None)
        return bool(is_junction and is_junction())
    except FileNotFoundError:
        return False
    except OSError:
        return True


def _contains_named_part(path: Path, names: set[str]) -> bool:
    parts = _lower_parts(path)
    return any(part in names or part.endswith(".egg-info") for part in parts)


def _is_codex_local_state_path(path: Path) -> bool:
    parts = _lower_parts(path)
    return any(
        pair in {(".codex", "cache"), (".codex", "sessions")}
        for pair in zip(parts, parts[1:])
    )


def _is_generated_file(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith((".pyc", ".pyo")) or any(
        part.startswith(".tc-guard-test-") for part in _lower_parts(path)
    )


def is_scan_excluded(path: Path) -> bool:
    return (
        _contains_named_part(path, SCAN_EXCLUDED_PARTS)
        or _is_codex_local_state_path(path)
        or _is_generated_file(path)
    )


def is_release_excluded(path: Path) -> bool:
    return (
        _contains_named_part(path, RELEASE_EXCLUDED_PARTS)
        or _is_codex_local_state_path(path)
        or _is_generated_file(path)
        or _lower_parts(path) in RELEASE_EXCLUDED_EXACT_PATHS
    )
