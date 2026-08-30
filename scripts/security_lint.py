from __future__ import annotations

import ast
import os
import tomllib
from pathlib import Path

try:
    from .project_safety import forbidden_path_reason, is_link_like, is_scan_excluded
except ImportError:  # Direct script execution.
    from project_safety import forbidden_path_reason, is_link_like, is_scan_excluded

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

FORBIDDEN_IMPORTS = {
    "aiohttp",
    "asyncio",
    "ctypes",
    "ftplib",
    "http.client",
    "http.server",
    "httpx",
    "imaplib",
    "multiprocessing",
    "nntplib",
    "paramiko",
    "poplib",
    "requests",
    "smtplib",
    "socket",
    "socketserver",
    "subprocess",
    "telnetlib",
    "urllib3",
    "urllib.request",
    "webbrowser",
    "websocket",
    "xmlrpc.client",
}
FORBIDDEN_CALL_NAMES = {"eval", "exec"}
FORBIDDEN_CALL_ATTRIBUTES = {
    "HTTPConnection",
    "HTTPSConnection",
    "create_connection",
    "environ",
    "execl",
    "execle",
    "execlp",
    "execlpe",
    "execv",
    "execve",
    "execvp",
    "execvpe",
    "expanduser",
    "getenv",
    "home",
    "open_connection",
    "popen",
    "spawnl",
    "spawnle",
    "spawnlp",
    "spawnlpe",
    "spawnv",
    "spawnve",
    "spawnvp",
    "spawnvpe",
    "start_server",
    "startfile",
    "system",
    "urlopen",
}
EXPECTED_COMMANDS = {"inspect", "verify-ledger"}
EXPECTED_ENTRY_POINTS = {"tc-guard": "technocore_guard.cli:main"}
EXPECTED_INSPECTION_FIELDS = {
    "schema",
    "method",
    "origin",
    "effect",
    "risk",
    "route_id",
    "sanitized_target",
    "reason",
    "warnings",
    "contains_private_capability",
    "contains_user_content",
    "contains_replay_material",
    "network_executed",
}


def fail(message: str) -> None:
    raise SystemExit(f"SECURITY LINT FAILED: {message}")


def imported_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
            names.update(f"{node.module}.{alias.name}" for alias in node.names)
    return names


def dynamic_import_lines(tree: ast.AST) -> list[int]:
    lines: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        direct = isinstance(node.func, ast.Name) and node.func.id == "__import__"
        via_importlib = isinstance(node.func, ast.Attribute) and node.func.attr == "import_module"
        if direct or via_importlib:
            lines.append(node.lineno)
    return sorted(lines)


def effectful_call_lines(tree: ast.AST) -> list[int]:
    lines: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "environ":
            lines.add(node.lineno)
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name) and node.func.id in FORBIDDEN_CALL_NAMES:
            lines.add(node.lineno)
        if isinstance(node.func, ast.Attribute) and node.func.attr in FORBIDDEN_CALL_ATTRIBUTES:
            lines.add(node.lineno)
    return sorted(lines)


def parser_commands(tree: ast.AST) -> set[str]:
    commands: set[str] = set()
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_parser"
        ):
            continue
        if (
            not node.args
            or not isinstance(node.args[0], ast.Constant)
            or not isinstance(node.args[0].value, str)
        ):
            fail("CLI subcommands must be fixed string literals")
        commands.add(node.args[0].value)
    return commands


def annotated_fields(tree: ast.AST, class_name: str) -> set[str]:
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            return {
                statement.target.id
                for statement in node.body
                if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name)
            }
    fail(f"required dataclass {class_name} is missing")
    return set()


def scan_project_paths() -> int:
    file_count = 0
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
                fail("link-like entry found inside the project")
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
                fail("link-like entry found inside the project")
            if not is_scan_excluded(relative) and candidate.is_file():
                file_count += 1
    return file_count


def main() -> None:
    file_count = scan_project_paths()
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    if project.get("dependencies") != []:
        fail("runtime dependencies must remain empty")
    if project.get("scripts") != EXPECTED_ENTRY_POINTS:
        fail("project entry points must remain exactly tc-guard")

    python_files = sorted(SRC.rglob("*.py"))
    parsed_files: dict[Path, ast.AST] = {}
    for path in python_files:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        parsed_files[path] = tree
        for name in imported_names(tree):
            if any(name == blocked or name.startswith(blocked + ".") for blocked in FORBIDDEN_IMPORTS):
                fail(f"network-capable import {name!r} in {path.relative_to(ROOT)}")
        lines = dynamic_import_lines(tree)
        if lines:
            fail(f"dynamic import call in {path.relative_to(ROOT)}")
        lines = effectful_call_lines(tree)
        if lines:
            fail(f"network, subprocess, or credential access call in {path.relative_to(ROOT)}")

    cli_tree = parsed_files[SRC / "technocore_guard" / "cli.py"]
    command_names = parser_commands(cli_tree)
    if command_names != EXPECTED_COMMANDS:
        fail("runtime CLI commands must remain exactly inspect and verify-ledger")

    models_tree = parsed_files[SRC / "technocore_guard" / "models.py"]
    field_names = annotated_fields(models_tree, "Inspection")
    if field_names != EXPECTED_INSPECTION_FIELDS:
        fail("Inspection fields no longer match the fixed public schema")

    print(
        "SECURITY LINT OK: "
        f"{len(python_files)} runtime Python files, {file_count} reviewable project files, "
        f"commands={sorted(command_names)}"
    )


if __name__ == "__main__":
    main()
