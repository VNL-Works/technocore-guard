from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable

try:
    from .project_safety import forbidden_path_reason, is_link_like, is_release_excluded
except ImportError:  # Direct script execution.
    from project_safety import forbidden_path_reason, is_link_like, is_release_excluded

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
MANIFEST_PATH = DIST / "release-manifest.json"
CHECKSUM_PATH = DIST / "release-manifest.sha256"


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


def _safe_path(relative: Path) -> Path:
    if relative.is_absolute() or ".." in relative.parts:
        raise SystemExit("unsafe release input path")
    if forbidden_path_reason(relative):
        raise SystemExit("identity or credential material is forbidden in release inputs")
    candidate = ROOT / relative
    for component in (candidate, *candidate.parents):
        if component == ROOT.parent:
            break
        if is_link_like(component):
            raise SystemExit("link-like paths are not release inputs")
    try:
        candidate.resolve(strict=True).relative_to(ROOT.resolve(strict=True))
    except (FileNotFoundError, ValueError) as exc:
        raise SystemExit("release input escapes the project or is missing") from exc
    return candidate


def _walk_files() -> list[Path]:
    files: list[Path] = []
    for current, dirnames, filenames in os.walk(ROOT, followlinks=False):
        current_path = Path(current)
        kept_directories: list[str] = []
        for name in dirnames:
            candidate = current_path / name
            relative = candidate.relative_to(ROOT)
            if forbidden_path_reason(relative):
                raise SystemExit("identity or credential material exists in the project")
            if is_link_like(candidate):
                raise SystemExit("link-like paths are not release inputs")
            if not is_release_excluded(relative):
                kept_directories.append(name)
        dirnames[:] = kept_directories
        for filename in filenames:
            relative = (current_path / filename).relative_to(ROOT)
            candidate = ROOT / relative
            if forbidden_path_reason(relative):
                raise SystemExit("identity or credential material exists in the project")
            if is_link_like(candidate):
                raise SystemExit("link-like paths are not release inputs")
            if is_release_excluded(relative):
                continue
            files.append(relative)
    return sorted(files, key=lambda value: value.as_posix())


def _tracked_files() -> list[Path]:
    output = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout
    return sorted(
        (Path(raw.decode("utf-8")) for raw in output.split(b"\0") if raw),
        key=lambda value: value.as_posix(),
    )


def _file_rows(paths: Iterable[Path]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for relative in paths:
        if is_release_excluded(relative):
            continue
        path = _safe_path(relative)
        if not path.is_file():
            continue
        data = path.read_bytes()
        rows.append(
            {
                "path": relative.as_posix(),
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    return rows


def _project_version() -> str:
    import tomllib

    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"][
        "version"
    ]


def _has_verified_local_git() -> bool:
    marker = ROOT / ".git"
    if not marker.exists():
        return False
    if is_link_like(marker) or not marker.is_dir():
        raise SystemExit("local .git must be a regular in-project directory")
    top_level = _git("rev-parse", "--show-toplevel")
    try:
        matches_root = Path(top_level).resolve(strict=True) == ROOT.resolve(strict=True)
    except (OSError, ValueError) as exc:
        raise SystemExit("local Git top level cannot be validated") from exc
    if not matches_root:
        raise SystemExit("local Git top level does not match the project root")
    return True


def _has_head() -> bool:
    result = subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD"],
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode == 0:
        return True
    if result.returncode in {1, 128}:
        return False
    raise SystemExit("local Git HEAD cannot be validated")


def build_manifest(*, require_clean_git: bool) -> dict[str, object]:
    has_git = _has_verified_local_git()
    if require_clean_git and not has_git:
        raise SystemExit("release manifest creation requires a real Git checkout")

    if has_git:
        dirty = bool(_git("status", "--porcelain"))
        if require_clean_git and dirty:
            raise SystemExit("refusing to build release evidence from a dirty Git tree")
        if _has_head():
            commit = _git("rev-parse", "HEAD")
            commit_time = _git("show", "-s", "--format=%cI", "HEAD")
            paths = _tracked_files()
        else:
            if require_clean_git:
                raise SystemExit("release manifest creation requires a committed Git HEAD")
            commit = "uncommitted-source-tree"
            commit_time = None
            paths = _walk_files()
    else:
        dirty = True
        commit = "uncommitted-source-tree"
        commit_time = None
        paths = _walk_files()

    rows = _file_rows(paths)
    return {
        "schema": "technocore-guard-release-manifest-v1",
        "project": "technocore-guard",
        "version": _project_version(),
        "git_commit": commit,
        "git_commit_time": commit_time,
        "git_dirty": dirty,
        "files": rows,
        "files_count": len(rows),
        "private_material_included": False,
    }


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
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
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Validate manifest construction without writing files or requiring Git.",
    )
    args = parser.parse_args()

    manifest = build_manifest(require_clean_git=not args.check_only)
    encoded = (json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode(
        "utf-8"
    )
    digest = hashlib.sha256(encoded).hexdigest()
    if args.check_only:
        print(
            f"MANIFEST CHECK OK: {manifest['files_count']} files, "
            f"version={manifest['version']}, sha256={digest}"
        )
        return

    _atomic_write(MANIFEST_PATH, encoded)
    _atomic_write(CHECKSUM_PATH, f"{digest}  {MANIFEST_PATH.name}\n".encode("ascii"))
    print(MANIFEST_PATH)
    print(CHECKSUM_PATH)
    print(digest)


if __name__ == "__main__":
    main()
