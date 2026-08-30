#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
python scripts/preflight.py
command -v codex >/dev/null 2>&1 || { echo "codex command was not found" >&2; exit 1; }
exec codex --sandbox workspace-write --ask-for-approval on-request \
  -c 'sandbox_workspace_write.network_access=false' \
  -c 'web_search="disabled"' \
  -c 'approvals_reviewer="user"'
