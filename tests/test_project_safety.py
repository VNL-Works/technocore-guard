from __future__ import annotations

import re
import unittest
from pathlib import Path
from unittest import mock

from _repo_test_support import ROOT, project_temp_dir
from scripts import build_release_manifest, project_safety


class ProjectSafetyTests(unittest.TestCase):
    def test_credential_and_identity_paths_are_recognized_without_opening_them(self) -> None:
        from scripts.project_safety import forbidden_path_reason

        forbidden = [
            Path(".secrets") / "material",
            Path(".agent") / "state",
            Path(".ssh") / "id_ed25519",
            Path("id_ed25519"),
            Path(".aws") / "credentials",
            Path(".codex") / "auth.json",
            Path(".claude") / ".credentials.json",
            Path(".config") / "gh" / "hosts.yml",
            Path(".npmrc"),
            Path(".netrc"),
            Path(".env"),
            Path("wallet.json"),
            Path("operator_seed.txt"),
            Path("mnemonic.txt"),
            Path("api_key.txt"),
            Path("access_token.txt"),
            Path("private.pem"),
            Path("client_secret.json"),
        ]
        for path in forbidden:
            with self.subTest(kind=path.suffix or path.name):
                self.assertIsNotNone(forbidden_path_reason(path))

        for path in (Path("README.md"), Path("docs") / "THREAT_MODEL.md"):
            self.assertIsNone(forbidden_path_reason(path))

    def test_generated_and_session_paths_are_not_release_inputs(self) -> None:
        from scripts.project_safety import is_release_excluded

        excluded = [
            Path(".codex") / "sessions" / "state.json",
            Path(".codex") / "cache" / "tool-output.json",
            Path("pkg.egg-info") / "PKG-INFO",
            Path("src") / "module.pyc",
            Path(".tc-guard") / "local.jsonl",
            Path("evidence") / "local.jsonl",
            Path("dist") / "release-manifest.json",
            Path("handoff.md"),
            Path("review.md"),
        ]
        for path in excluded:
            with self.subTest(suffix=path.suffix):
                self.assertTrue(is_release_excluded(path))
        self.assertFalse(is_release_excluded(Path("src") / "technocore_guard" / "classifier.py"))

    def test_release_config_enforces_lf_and_defense_in_depth_ignores(self) -> None:
        attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
        ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("* text=auto eol=lf", attributes)
        for pattern in (
            ".codex/cache/",
            "evidence/*",
            "*.jsonl",
            ".coverage*",
            ".ssh/",
            ".aws/",
            ".npmrc",
            ".netrc",
            "*.pem",
        ):
            with self.subTest(pattern=pattern):
                self.assertIn(pattern, ignore)

    def test_public_ci_is_pinned_least_privilege_and_install_free(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("name: CI\n", workflow)
        self.assertIn(
            "on:\n"
            "  push:\n"
            "    branches:\n"
            "      - main\n"
            "  pull_request:\n"
            "  workflow_dispatch:\n",
            workflow,
        )
        permission_headers = [
            line for line in workflow.splitlines() if line.strip() == "permissions:"
        ]
        self.assertEqual(permission_headers, ["permissions:"])
        self.assertIn("\npermissions:\n  contents: read\n\n", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("timeout-minutes: 15", workflow)
        self.assertIn("fail-fast: false", workflow)
        for value in ('ubuntu-latest', 'windows-latest', '"3.11"', '"3.12"', '"3.13"'):
            with self.subTest(matrix_value=value):
                self.assertIn(f"- {value}", workflow)

        uses = [
            line.strip()
            for line in workflow.splitlines()
            if line.strip().startswith("uses: ")
        ]
        self.assertEqual(
            uses,
            [
                "uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                "uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
            ],
        )

        runs = [
            line.strip().removeprefix("run: ")
            for line in workflow.splitlines()
            if line.strip().startswith("run: ")
        ]
        self.assertEqual(
            runs,
            [
                "python scripts/preflight.py",
                "python -m unittest discover -s tests -v",
                "python -m compileall -q src tests scripts",
                "python scripts/security_lint.py",
                "python scripts/build_release_manifest.py --check-only",
                "git diff --check HEAD",
            ],
        )

        lowered = workflow.casefold()
        for forbidden in (
            "pull_request_target:",
            "workflow_run:",
            "secrets.",
            "secrets[",
            "secrets:",
            "write-all",
            "upload-artifact",
            "create-release",
            "action-gh-release",
            "gh release",
            "curl ",
            "wget ",
            "invoke-webrequest",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, lowered)
        self.assertIsNone(re.search(r"\bpip(?:3)?\s+install\b", lowered))
        self.assertIsNone(re.search(r"\$\{\{[^}]*\bsecrets\b[^}]*\}\}", lowered))
        self.assertIsNone(
            re.search(r"(?m)^\s+[a-z][a-z-]*:\s+write\s*$", workflow)
        )

    def test_release_documentation_states_frozen_scope_and_ledger_limits(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        for statement in (
            "# Technocore Capability Guard",
            "Technocore Capability Guard v0.1.0",
            "Offline, fail-closed effect classifier and tamper-evident local ledger",
            "This project is neither a fork nor a replacement for Technocore Link Guard",
            "not an official Technocore tool",
            "clean-looking classification is not a safety guarantee",
            "The runtime implements no network access",
            "infrastructure activity is a separate layer from the runtime no-network guarantee",
            "`[project].version` in `pyproject.toml` is authoritative",
            "tamper-evident, not tamper-proof",
            "trusted external checkpoint",
            "Concurrent writers are outside the v0.1.0 scope",
            "human-reviewed fixed snapshot",
            "never updates it automatically",
            "`inspect` and `verify-ledger`",
        ):
            with self.subTest(statement=statement):
                self.assertIn(statement, readme)
        self.assertIn(
            "https://github.com/devorun/technocore-link-guard",
            readme,
        )
        self.assertIn("## 0.1.0", changelog)
        self.assertNotIn("http://", changelog)
        self.assertNotIn("https://", changelog)

    def test_manifest_path_guard_rejects_sensitive_names_before_resolution(self) -> None:
        from scripts.build_release_manifest import _safe_path

        for relative in (Path(".env"), Path("wallet.json"), Path(".codex") / "auth.json"):
            with self.subTest(suffix=relative.suffix), self.assertRaises(SystemExit) as captured:
                _safe_path(relative)
            self.assertNotIn(relative.as_posix(), str(captured.exception))

    def test_manifest_path_guard_rejects_a_link_component(self) -> None:
        from scripts.build_release_manifest import _safe_path

        with project_temp_dir() as directory:
            real = directory / "real"
            real.mkdir()
            link = directory / "link"
            try:
                link.symlink_to(real, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symlink creation is unavailable: {type(exc).__name__}")
            (real / "artifact.txt").write_text("synthetic", encoding="utf-8")
            relative = (link / "artifact.txt").relative_to(ROOT)
            with self.assertRaises(SystemExit):
                _safe_path(relative)

    def test_windows_reparse_attribute_is_treated_as_link_like(self) -> None:
        synthetic = type("SyntheticStat", (), {"st_file_attributes": 0x0400})()
        with (
            mock.patch.object(project_safety.Path, "is_symlink", return_value=False),
            mock.patch.object(project_safety.Path, "is_junction", return_value=False, create=True),
            mock.patch.object(project_safety.os, "lstat", return_value=synthetic),
        ):
            self.assertTrue(project_safety.is_link_like(Path("synthetic")))

    def test_manifest_rejects_link_before_resolving_its_target(self) -> None:
        with project_temp_dir() as directory:
            real = directory / "real"
            real.mkdir()
            link = directory / "link"
            try:
                link.symlink_to(real, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symlink creation is unavailable: {type(exc).__name__}")
            relative = link.relative_to(ROOT)
            with (
                mock.patch.object(Path, "resolve", side_effect=AssertionError("resolved link")),
                self.assertRaises(SystemExit),
            ):
                build_release_manifest._safe_path(relative)

    def test_manifest_rejects_a_git_pointer_file_before_invoking_git(self) -> None:
        with project_temp_dir() as directory:
            (directory / ".git").write_text("gitdir: external-location\n", encoding="utf-8")
            with (
                mock.patch.object(build_release_manifest, "ROOT", directory),
                mock.patch.object(
                    build_release_manifest,
                    "_git",
                    side_effect=AssertionError("Git must not be invoked"),
                ),
                self.assertRaises(SystemExit),
            ):
                build_release_manifest._has_verified_local_git()

    def test_check_only_manifest_handles_an_unborn_local_repository(self) -> None:
        with (
            mock.patch.object(build_release_manifest, "_has_verified_local_git", return_value=True),
            mock.patch.object(build_release_manifest, "_git", return_value="?? README.md"),
            mock.patch.object(build_release_manifest, "_has_head", return_value=False, create=True),
            mock.patch.object(build_release_manifest, "_walk_files", return_value=[Path("README.md")]),
            mock.patch.object(
                build_release_manifest,
                "_tracked_files",
                side_effect=AssertionError("unborn repository must use the safe workspace walk"),
            ),
        ):
            manifest = build_release_manifest.build_manifest(require_clean_git=False)
        self.assertEqual(manifest["git_commit"], "uncommitted-source-tree")
        self.assertIsNone(manifest["git_commit_time"])
        self.assertTrue(manifest["git_dirty"])
        self.assertEqual(manifest["files_count"], 1)

    def test_release_manifest_write_requires_a_committed_head(self) -> None:
        with (
            mock.patch.object(build_release_manifest, "_has_verified_local_git", return_value=True),
            mock.patch.object(build_release_manifest, "_git", return_value=""),
            mock.patch.object(build_release_manifest, "_has_head", return_value=False, create=True),
            self.assertRaises(SystemExit),
        ):
            build_release_manifest.build_manifest(require_clean_git=True)


if __name__ == "__main__":
    unittest.main()
