from __future__ import annotations

import io
import json
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

try:
    from _repo_test_support import ROOT, SRC, project_temp_dir
except ImportError:  # Run as `python -m unittest tests.test_route_drift` from the root.
    from tests._repo_test_support import ROOT, SRC, project_temp_dir
from scripts import route_drift
from technocore_guard.classifier import STATIC_READ_PATHS

SAMPLE = ROOT / "tests" / "fixtures" / "route_drift" / "app_sample.py.txt"
COMMIT = "0123456789abcdef0123456789abcdef01234567"

CLEAN_TEMPLATE = """
_DOCS = {{"/skill.md": "x"}}

app = Starlette(
    routes=[
        *[Route(path, static_doc) for path in ({statics})],
        *[Route(path, doc_md) for path in _DOCS],
        Route("/rooms", rooms),
        Route("/r/{{room}}", room_read),
        Route("/r/{{room}}", room_post, methods=["POST"]),
        _get_write("/r/{{room}}/say/{{nick}}/{{text:path}}", room_say),
        _get_write("/r/{{room}}/say-signed/{{did}}/{{sig}}/{{nonce}}/{{text:path}}", room_say_signed),
        Route("/kv/{{ns}}", note_list),
        Route("/kv/{{ns}}/{{key}}", note_read),
        Route("/kv/{{ns}}/{{key}}", note_post, methods=["POST"]),
        _get_write("/kv/{{ns}}/{{key}}/set/{{value:path}}", note_write),
        _get_write("/kv/{{ns}}/{{key}}/set-signed/{{did}}/{{sig}}/{{nonce}}/{{value:path}}", note_write_signed),
    ],
)
"""


def clean_source() -> str:
    statics = sorted(STATIC_READ_PATHS - {"/skill.md"})
    return CLEAN_TEMPLATE.format(statics=", ".join(json.dumps(path) for path in statics))


class RouteDriftTests(unittest.TestCase):
    def run_main(self, argv: list[str]) -> tuple[int, str, str]:
        out = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = route_drift.main(argv)
        return code, out.getvalue(), err.getvalue()

    def run_source(self, source: str) -> tuple[int, str, str]:
        with project_temp_dir() as directory:
            app_py = directory / "app.py.txt"
            app_py.write_text(source, encoding="utf-8", newline="\n")
            return self.run_main(["--app-py", str(app_py), "--upstream-commit", COMMIT])

    def sample_report(self) -> tuple[int, dict]:
        code, out, err = self.run_main(["--app-py", str(SAMPLE), "--upstream-commit", COMMIT])
        self.assertIn(code, {0, 1}, err)
        return code, json.loads(out)

    # -- extraction ----------------------------------------------------------

    def test_all_five_forms_are_extracted_with_starlette_methods(self) -> None:
        _code, report = self.sample_report()
        routes = {row["path"]: row["methods"] for row in report["upstream_routes"]}
        self.assertEqual(
            routes,
            {
                "/": ["GET", "HEAD"],  # (d)
                "/llms.txt": ["GET", "HEAD"],  # (d)
                "/skill.md": ["GET", "HEAD"],  # (e)
                "/interop.md": ["GET", "HEAD"],  # (e)
                "/healthz": ["GET", "HEAD"],  # (a)
                "/stats": ["GET", "HEAD"],  # (a)
                "/rooms": ["GET", "HEAD"],  # (a)
                "/r/{room}": ["GET", "HEAD", "POST"],  # (a) + (b) merged
                "/r/{room}/export": ["GET", "HEAD"],  # (a)
                "/r/{room}/archive": ["POST"],  # (b) without GET has no HEAD
                "/r/{room}/say/{nick}/{text:path}": ["GET"],  # (c) has no HEAD
                "/r/{room}/poke/{nick}": ["GET"],  # (c)
            },
        )
        self.assertEqual(
            [row["path"] for row in report["upstream_routes"]],
            sorted(row["path"] for row in report["upstream_routes"]),
        )

    def test_methods_list_with_get_gains_head(self) -> None:
        source = 'app = Starlette(routes=[Route("/healthz", healthz, methods=["GET"])])\n'
        code, out, err = self.run_source(source)
        self.assertIn(code, {0, 1}, err)
        report = json.loads(out)
        self.assertEqual(report["upstream_routes"], [{"path": "/healthz", "methods": ["GET", "HEAD"]}])

    # -- fail closed ---------------------------------------------------------

    def assert_exit_2(self, source: str, shape: str) -> str:
        code, out, err = self.run_source(source)
        self.assertEqual(code, 2, err)
        self.assertEqual(out, "")
        self.assertIn(shape, err)
        self.assertNotIn("https://", err)
        return err

    def test_unknown_route_shape_exits_2_with_line_number(self) -> None:
        source = 'app = Starlette(\n    routes=[\n        Mount("/sub", other),\n    ],\n)\n'
        err = self.assert_exit_2(source, "unknown route shape")
        self.assertIn("line 3", err)

    def test_unknown_keyword_and_comprehension_shapes_exit_2(self) -> None:
        cases = (
            'app = Starlette(routes=[Route("/x", x, name="x")])\n',
            'app = Starlette(routes=[*[Route(p, x) for p in PATHS]])\n',
            'app = Starlette(routes=[*[Route(p, x) for p in ("/a",) if p]])\n',
            'app = Starlette(routes=[some_route])\n',
            'app = Starlette(routes=[Route("/x", x)])\napp.add_route("/y", y)\n',
        )
        for source in cases:
            with self.subTest(index=cases.index(source)):
                self.assert_exit_2(source, "line ")

    def test_non_literal_path_exits_2(self) -> None:
        source = 'PATH = "/x"\napp = Starlette(\n    routes=[\n        Route(PATH, x),\n    ],\n)\n'
        err = self.assert_exit_2(source, "non-literal path")
        self.assertIn("line 4", err)

    def test_non_literal_docs_key_exits_2(self) -> None:
        source = (
            'NAME = "/x.md"\n_DOCS = {NAME: "x"}\n'
            "app = Starlette(routes=[*[Route(path, doc_md) for path in _DOCS]])\n"
        )
        err = self.assert_exit_2(source, "non-literal _DOCS key")
        self.assertIn("line 2", err)

    def test_missing_app_exits_2(self) -> None:
        self.assert_exit_2('routes = [Route("/", x)]\n', "missing app")
        self.assert_exit_2('app = Starlette(debug=True)\n', "missing app")

    def test_unknown_placeholder_is_a_sample_error(self) -> None:
        self.assert_exit_2('app = Starlette(routes=[Route("/u/{user}", x)])\n', "unknown placeholder")

    def test_sample_refused_by_the_guard_is_sample_rejected(self) -> None:
        err = self.assert_exit_2('app = Starlette(routes=[Route("/a b", x)])\n', "sample_rejected")
        self.assertIn("raw-whitespace", err)

    def test_unmodelled_method_exits_2(self) -> None:
        source = 'app = Starlette(routes=[Route("/r/{room}", x, methods=["DELETE"])])\n'
        self.assert_exit_2(source, "unsupported method")

    def test_invalid_upstream_commit_exits_2(self) -> None:
        for commit in ("7707cb6", "0123456789ABCDEF0123456789ABCDEF01234567", COMMIT + "0"):
            with self.subTest(length=len(commit)):
                code, out, err = self.run_main(["--app-py", str(SAMPLE), "--upstream-commit", commit])
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertIn("--upstream-commit", err)

    def test_usage_error_exits_2(self) -> None:
        code, _out, err = self.run_main(["--upstream-commit", COMMIT])
        self.assertEqual(code, 2)
        self.assertIn("usage error", err)

    def test_guard_src_mismatch_exits_2(self) -> None:
        saved_path = list(sys.path)
        self.addCleanup(sys.path.__setitem__, slice(None), saved_path)
        with project_temp_dir() as directory:
            other = directory / "src"
            (other / "technocore_guard").mkdir(parents=True)
            (other / "technocore_guard" / "classifier.py").write_text("", encoding="utf-8")
            code, _out, err = self.run_main(
                ["--app-py", str(SAMPLE), "--upstream-commit", COMMIT, "--guard-src", str(other)]
            )
        self.assertEqual(code, 2)
        self.assertIn("guard src", err)

    # -- drift lists ---------------------------------------------------------

    def test_sample_reports_uncovered_misclassified_and_stale(self) -> None:
        code, report = self.sample_report()
        self.assertEqual(code, 1)
        self.assertTrue(report["drift"])
        self.assertEqual(report["schema"], "technocore-guard-route-drift-v1")
        self.assertEqual(report["upstream_commit"], COMMIT)
        uncovered = {(row["path"], row["method"]) for row in report["uncovered"]}
        self.assertEqual(
            uncovered,
            {
                ("/interop.md", "GET"),
                ("/interop.md", "HEAD"),
                ("/stats", "GET"),
                ("/stats", "HEAD"),
                ("/r/{room}/export", "GET"),
                ("/r/{room}/export", "HEAD"),
                ("/r/{room}/archive", "POST"),
                ("/r/{room}/poke/{nick}", "GET"),
            },
        )
        misclassified = {(row["path"], row["method"]) for row in report["write_misclassified"]}
        self.assertEqual(
            misclassified,
            {("/r/{room}/archive", "POST"), ("/r/{room}/poke/{nick}", "GET")},
        )
        upstream_paths = {row["path"] for row in report["upstream_routes"]}
        self.assertEqual(report["stale_static_paths"], sorted(STATIC_READ_PATHS - upstream_paths))
        self.assertIn("/patterns.md", report["stale_static_paths"])
        classified = {(row["path"], row["method"]): row for row in report["classified"]}
        self.assertEqual(classified[("/r/{room}", "POST")]["effect"], "write")
        self.assertEqual(classified[("/r/{room}/say/{nick}/{text:path}", "GET")]["route_id"], "unsigned-room-write")
        self.assertEqual(
            [(row["path"], row["method"]) for row in report["classified"]],
            sorted((row["path"], row["method"]) for row in report["classified"]),
        )

    def test_get_shaped_write_classified_as_read_is_misclassified_not_uncovered(self) -> None:
        source = clean_source().replace(
            'Route("/kv/{ns}", note_list)', '_get_write("/kv/{ns}", note_wipe)'
        )
        code, out, err = self.run_source(source)
        self.assertEqual(code, 1, err)
        report = json.loads(out)
        self.assertEqual(report["uncovered"], [])
        self.assertEqual(
            report["write_misclassified"],
            [{"effect": "read", "method": "GET", "path": "/kv/{ns}", "route_id": "list-notes"}],
        )

    def test_only_stale_static_path_sets_drift(self) -> None:
        source = clean_source().replace('"/healthz", ', "")
        code, out, err = self.run_source(source)
        self.assertEqual(code, 1, err)
        report = json.loads(out)
        self.assertEqual(report["stale_static_paths"], ["/healthz"])
        self.assertEqual(report["uncovered"], [])
        self.assertEqual(report["write_misclassified"], [])
        self.assertTrue(report["drift"])

    def test_clean_sample_exits_0(self) -> None:
        code, out, err = self.run_source(clean_source())
        self.assertEqual(code, 0, err)
        report = json.loads(out)
        self.assertFalse(report["drift"])
        self.assertEqual(report["uncovered"], [])
        self.assertEqual(report["write_misclassified"], [])
        self.assertEqual(report["stale_static_paths"], [])

    # -- output --------------------------------------------------------------

    def test_output_is_deterministic_and_free_of_urls_and_samples(self) -> None:
        with project_temp_dir() as directory:
            first = directory / "first.json"
            second = directory / "second.json"
            for out in (first, second):
                code, stdout, err = self.run_main(
                    ["--app-py", str(SAMPLE), "--upstream-commit", COMMIT, "--out", str(out)]
                )
                self.assertEqual(code, 1, err)
                self.assertEqual(stdout, "")
            data = first.read_bytes()
            self.assertEqual(data, second.read_bytes())
        self.assertTrue(data.endswith(b"}\n"))
        self.assertNotIn(b"\r", data)
        text = data.decode("utf-8")
        self.assertEqual(text, json.dumps(json.loads(text), sort_keys=True, indent=2) + "\n")
        for forbidden in ("https://", "http://", "technocore.chat", "did:key", "lobby", "hello"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)

    def test_fixture_out_layout(self) -> None:
        with project_temp_dir() as directory:
            fixture = directory / "fixture.json"
            code, _out, err = self.run_main(
                [
                    "--app-py",
                    str(SAMPLE),
                    "--upstream-commit",
                    COMMIT,
                    "--fixture-out",
                    str(fixture),
                ]
            )
            self.assertEqual(code, 1, err)
            data = fixture.read_bytes()
        self.assertNotIn(b"\r", data)
        payload = json.loads(data)
        self.assertEqual(list(payload), ["source", "commit", "routes"])
        self.assertEqual(payload["source"], "technocore-chat/src/app.py route registry")
        self.assertEqual(payload["commit"], COMMIT)
        routes = payload["routes"]
        self.assertEqual([row[0] for row in routes], sorted(row[0] for row in routes))
        self.assertIn(["/r/{room}", ["GET", "HEAD", "POST"]], routes)
        self.assertIn(["/r/{room}/say/{nick}/{text:path}", ["GET"]], routes)
        for row in routes:
            self.assertEqual(len(row), 2)
            self.assertEqual(row[1], sorted(row[1]))

    def test_script_has_no_forbidden_imports_or_calls(self) -> None:
        import ast

        from scripts.security_lint import (
            FORBIDDEN_IMPORTS,
            dynamic_import_lines,
            effectful_call_lines,
            imported_names,
        )

        tree = ast.parse((ROOT / "scripts" / "route_drift.py").read_text(encoding="utf-8"))
        bad = sorted(
            name
            for name in imported_names(tree)
            if any(name == blocked or name.startswith(blocked + ".") for blocked in FORBIDDEN_IMPORTS)
            or name == "http"
            or name.startswith("http.")
        )
        self.assertEqual(bad, [])
        self.assertEqual(dynamic_import_lines(tree), [])
        self.assertEqual(effectful_call_lines(tree), [])

    def test_default_guard_src_is_this_repository(self) -> None:
        self.assertEqual(Path(route_drift.DEFAULT_GUARD_SRC).resolve(), SRC.resolve())


if __name__ == "__main__":
    unittest.main()
