from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
MANIFEST = DIST / "release-manifest.json"
OUTPUT = DIST / "release-anchor.txt"
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
REPO_PATH_RE = re.compile(r"^/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def _repository(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.netloc.lower() != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.query
        or parsed.fragment
        or not REPO_PATH_RE.fullmatch(parsed.path.rstrip("/"))
    ):
        raise SystemExit("repository must be a canonical public https://github.com/OWNER/REPO URL")
    return f"https://github.com{parsed.path.rstrip('/')}"


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except BaseException:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description="Render, but never send, a release anchor line.")
    parser.add_argument("--version", required=True)
    parser.add_argument("--repository", required=True)
    args = parser.parse_args()

    if not VERSION_RE.fullmatch(args.version):
        raise SystemExit("version must be a SemVer-like value such as 0.1.0")
    repository = _repository(args.repository)
    if not MANIFEST.is_file() or MANIFEST.is_symlink():
        raise SystemExit("dist/release-manifest.json is missing or unsafe")
    data = MANIFEST.read_bytes()
    try:
        manifest = json.loads(data)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"release manifest is invalid JSON: {exc}") from exc
    if manifest.get("version") != args.version:
        raise SystemExit("requested version does not match the release manifest")
    commit = manifest.get("git_commit")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise SystemExit("release manifest does not contain a full Git commit SHA")
    digest = hashlib.sha256(data).hexdigest()
    line = (
        f"Released Technocore Guard v{args.version}: offline URL effect classification, "
        f"no network or signing. repo {repository} commit {commit} manifest_sha256 {digest}"
    )
    if len(line) > 4096 or "\n" in line or "\r" in line:
        raise SystemExit("anchor does not fit the single-line message contract")
    _atomic_write(OUTPUT, line + "\n")
    print(line)
    print(f"draft written to {OUTPUT}; nothing was sent")


if __name__ == "__main__":
    main()
