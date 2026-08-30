$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Push-Location $Root
try {
    python scripts/preflight.py
    if (-not (Get-Command codex -ErrorAction SilentlyContinue)) {
        throw "codex command was not found"
    }
    codex --sandbox workspace-write --ask-for-approval on-request `
      -c 'sandbox_workspace_write.network_access=false' `
      -c 'web_search="disabled"' `
      -c 'approvals_reviewer="user"' `
      -c 'windows.sandbox="elevated"'
}
finally {
    Pop-Location
}
