from __future__ import annotations

import ast
import dataclasses
import os
import shutil
import subprocess
import tomllib
import unittest
from pathlib import Path

from _repo_test_support import ROOT
from scripts.project_safety import forbidden_path_reason, is_link_like, is_scan_excluded
from scripts.security_lint import (
    FORBIDDEN_IMPORTS,
    dynamic_import_lines,
    effectful_call_lines,
    imported_names,
    parser_commands,
)
from technocore_guard.cli import build_parser
from technocore_guard.models import Inspection, PUBLIC_EVENT_FIELDS

SRC = ROOT / "src"


class NoNetworkOrSecretsTests(unittest.TestCase):
    def test_runtime_has_no_network_capable_imports(self) -> None:
        for path in SRC.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            names = imported_names(tree)
            bad = sorted(
                name
                for name in names
                if any(name == blocked or name.startswith(blocked + ".") for blocked in FORBIDDEN_IMPORTS)
            )
            self.assertEqual(bad, [], f"{path}: {bad}")
            self.assertEqual(dynamic_import_lines(tree), [], path)

    def test_repository_contains_no_identity_material_paths(self) -> None:
        for current, dirnames, filenames in os.walk(ROOT, followlinks=False):
            current_path = Path(current)
            kept_directories: list[str] = []
            for name in dirnames:
                path = current_path / name
                relative = path.relative_to(ROOT)
                self.assertIsNone(forbidden_path_reason(relative), relative.suffix)
                self.assertFalse(is_link_like(path), relative.suffix)
                if not is_scan_excluded(relative):
                    kept_directories.append(name)
            dirnames[:] = kept_directories
            for name in filenames:
                path = current_path / name
                relative = path.relative_to(ROOT)
                self.assertIsNone(forbidden_path_reason(relative), relative.suffix)
                self.assertFalse(is_link_like(path), relative.suffix)

    def test_cli_exposes_no_outbound_or_signing_command(self) -> None:
        parser = build_parser()
        commands: set[str] = set()
        for action in parser._actions:
            choices = getattr(action, "choices", None)
            if isinstance(choices, dict):
                commands.update(choices)
        self.assertEqual(commands, {"inspect", "verify-ledger"})
        forbidden = {
            "claim",
            "commit-write",
            "faucet",
            "fetch",
            "safe-read",
            "say",
            "sign",
            "wallet",
            "write",
        }
        self.assertFalse(commands & forbidden)
        fields = {field.name for field in dataclasses.fields(Inspection)}
        self.assertFalse(fields & {"raw_url", "input_sha256", "signature", "nonce", "text", "value"})
        self.assertEqual(fields, set(PUBLIC_EVENT_FIELDS))

    def test_network_import_scanner_catches_from_import_form(self) -> None:
        cases = {
            "from urllib import request": "urllib.request",
            "from http.client import HTTPSConnection": "http.client",
            "import subprocess": "subprocess",
        }
        for source, expected in cases.items():
            with self.subTest(expected=expected):
                self.assertIn(expected, imported_names(ast.parse(source)))

    def test_dynamic_import_scanner_rejects_literal_and_importlib_forms(self) -> None:
        for source in ('__import__("socket")', 'importlib.import_module("http.client")'):
            with self.subTest(call=source.split("(", 1)[0]):
                self.assertTrue(dynamic_import_lines(ast.parse(source)))

    def test_effectful_call_scanner_rejects_subprocess_and_credential_access(self) -> None:
        cases = (
            "os.system('command')",
            "os.popen('command')",
            "os.getenv('NAME')",
            "Path.home()",
            "urllib.request.urlopen('value')",
        )
        for source in cases:
            with self.subTest(call=source.split("(", 1)[0]):
                self.assertTrue(effectful_call_lines(ast.parse(source)))

    def test_static_cli_and_entry_point_inventory_is_exact(self) -> None:
        cli_tree = ast.parse((SRC / "technocore_guard" / "cli.py").read_text(encoding="utf-8"))
        self.assertEqual(parser_commands(cli_tree), {"inspect", "verify-ledger"})
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        self.assertEqual(project["scripts"], {"tc-guard": "technocore_guard.cli:main"})

    def test_security_linter_does_not_import_the_runtime_under_review(self) -> None:
        source = (ROOT / "scripts" / "security_lint.py").read_text(encoding="utf-8")
        self.assertNotIn("from technocore_guard", source)
        self.assertNotIn("import technocore_guard", source)

    def test_quality_scripts_only_run_git_for_a_local_checkout(self) -> None:
        powershell = (ROOT / "scripts" / "quality.ps1").read_text(encoding="utf-8")
        shell = (ROOT / "scripts" / "quality.sh").read_text(encoding="utf-8")
        self.assertIn('Join-Path $Root ".git"', powershell)
        self.assertIn('"$ROOT/.git"', shell)
        self.assertNotIn("rev-parse --is-inside-work-tree", powershell)
        self.assertNotIn("rev-parse --is-inside-work-tree", shell)
        self.assertIn("git -C $Root diff --check", powershell)
        self.assertIn('git -C "$ROOT" diff --check', shell)
        self.assertIn("PSIsContainer", powershell)
        self.assertIn("ReparsePoint", powershell)
        self.assertIn('! -d "$ROOT/.git"', shell)
        self.assertIn('-L "$ROOT/.git"', shell)

    def test_every_powershell_python_gate_checks_its_exit_code(self) -> None:
        lines = [
            line.strip()
            for line in (ROOT / "scripts" / "quality.ps1").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        python_lines = [index for index, line in enumerate(lines) if line.startswith("python ")]
        self.assertEqual(len(python_lines), 5)
        for index in python_lines:
            with self.subTest(command=lines[index].split()[1]):
                self.assertEqual(lines[index + 1], "if ($LASTEXITCODE -ne 0) { throw \"Python validation failed\" }")

    def test_powershell_quality_gate_stops_after_a_synthetic_python_failure(self) -> None:
        powershell = shutil.which("PowerShell")
        if powershell is None:
            self.skipTest("Windows PowerShell is unavailable")
        quality = str(ROOT / "scripts" / "quality.ps1").replace("'", "''")
        probe = f"""
$global:Calls = 0
function global:python {{
    $global:Calls += 1
    $global:LASTEXITCODE = 23
}}
try {{
    & '{quality}'
}}
catch {{
    Write-Output ('calls=' + $global:Calls)
    exit 23
}}
Write-Output ('calls=' + $global:Calls)
exit 0
"""
        completed = subprocess.run(
            [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", probe],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout.strip(), "calls=1")


if __name__ == "__main__":
    unittest.main()
