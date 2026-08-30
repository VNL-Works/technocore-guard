#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
python scripts/preflight.py
python -m unittest discover -s tests -v
python -m compileall -q src tests scripts
python scripts/security_lint.py
python scripts/build_release_manifest.py --check-only
if [[ -e "$ROOT/.git" || -L "$ROOT/.git" ]]; then
  if [[ ! -d "$ROOT/.git" || -L "$ROOT/.git" ]]; then
    echo "local .git must be a regular in-project directory" >&2
    exit 1
  fi
  command -v git >/dev/null 2>&1 || { echo "git command is unavailable" >&2; exit 1; }
  TOP_LEVEL="$(git -C "$ROOT" rev-parse --show-toplevel)"
  if [[ "${TOP_LEVEL%/}" != "${ROOT%/}" ]]; then
    echo "local Git top level does not match project root" >&2
    exit 1
  fi
  git -C "$ROOT" diff --check
fi
