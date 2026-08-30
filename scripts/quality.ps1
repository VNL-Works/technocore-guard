$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Push-Location $Root
try {
    python scripts/preflight.py
    if ($LASTEXITCODE -ne 0) { throw "Python validation failed" }
    python -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { throw "Python validation failed" }
    python -m compileall -q src tests scripts
    if ($LASTEXITCODE -ne 0) { throw "Python validation failed" }
    python scripts/security_lint.py
    if ($LASTEXITCODE -ne 0) { throw "Python validation failed" }
    python scripts/build_release_manifest.py --check-only
    if ($LASTEXITCODE -ne 0) { throw "Python validation failed" }
    $LocalGit = Join-Path $Root ".git"
    if (Test-Path -LiteralPath $LocalGit) {
        $GitMarker = Get-Item -LiteralPath $LocalGit -Force
        if ((-not $GitMarker.PSIsContainer) -or ($GitMarker.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "local .git must be a regular in-project directory"
        }
        if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw "git command is unavailable" }
        $TopLevel = git -C $Root rev-parse --show-toplevel 2>$null
        if ($LASTEXITCODE -ne 0) { throw "local .git exists but cannot be inspected" }
        $ExpectedTop = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
        $ActualTop = [IO.Path]::GetFullPath($TopLevel).TrimEnd('\', '/')
        if ($ActualTop -ne $ExpectedTop) { throw "local Git top level does not match project root" }
        git -C $Root diff --check
        if ($LASTEXITCODE -ne 0) { throw "git diff --check failed" }
    }
}
finally {
    Pop-Location
}
