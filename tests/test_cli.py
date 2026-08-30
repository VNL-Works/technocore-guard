from __future__ import annotations

import io
import hashlib
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from _repo_test_support import project_temp_dir
from technocore_guard.cli import main


DID = "did:key:z6Mk" + "1" * 44
SIG = "A" * 86


class CliTests(unittest.TestCase):
    def run_cli(self, argv: list[str], stdin: str = "") -> tuple[int, str, str]:
        out = io.StringIO()
        err = io.StringIO()
        with patch("sys.stdin", io.StringIO(stdin)), redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_private_inspection_output_is_redacted(self) -> None:
        private = "p-never-print-this"
        code, out, err = self.run_cli(["inspect", f"https://technocore.chat/r/{private}"])
        self.assertEqual(code, 0, err)
        self.assertNotIn(private, out)
        payload = json.loads(out)
        self.assertEqual(payload["sanitized_target"], "/r/<private-room>")

    def test_unknown_route_returns_nonzero(self) -> None:
        code, out, _err = self.run_cli(["inspect", "https://technocore.chat/faucet"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)["effect"], "unknown")

    def test_record_then_verify(self) -> None:
        with project_temp_dir() as directory:
            ledger = directory / "ledger.jsonl"
            code, out, err = self.run_cli(
                ["inspect", "https://technocore.chat/llms.txt", "--record", str(ledger)]
            )
            self.assertEqual(code, 0, err)
            payload = json.loads(out)
            self.assertIn("ledger_record_sha256", payload)
            self.assertTrue(payload["ledger_recorded"])
            self.assertNotIn("ledger_path", payload)
            self.assertNotIn(str(ledger), out)
            code, out, err = self.run_cli(["verify-ledger", str(ledger)])
            self.assertEqual(code, 0, err)
            self.assertTrue(json.loads(out)["valid"])

    def test_missing_ledger_fails(self) -> None:
        with project_temp_dir() as directory:
            path = directory / "p-missing-ledger-capability.jsonl"
            code, _out, err = self.run_cli(["verify-ledger", str(path)])
            self.assertEqual(code, 2)
            self.assertIn("does not exist", err)
            self.assertNotIn(str(path), err)
            self.assertNotIn("p-missing-ledger-capability", err)

    def test_stdin_accepts_exactly_one_line_without_echoing_it(self) -> None:
        private = "p-stdin-capability"
        raw = f"https://technocore.chat/r/{private}\n"
        code, out, err = self.run_cli(["inspect", "-"], stdin=raw)
        self.assertEqual(code, 0, err)
        self.assertNotIn(private, out)

    def test_stdin_rejects_multiple_lines(self) -> None:
        code, _out, err = self.run_cli(
            ["inspect", "-"],
            stdin="https://technocore.chat/llms.txt\nhttps://technocore.chat/healthz\n",
        )
        self.assertEqual(code, 2)
        self.assertIn("exactly one URL line", err)

    def test_stdin_rejects_trailing_blank_lines(self) -> None:
        code, _out, err = self.run_cli(
            ["inspect", "-"],
            stdin="https://technocore.chat/llms.txt\n\n",
        )
        self.assertEqual(code, 2)
        self.assertIn("exactly one URL line", err)

    def test_invalid_method_is_blocked_without_reflecting_it(self) -> None:
        secret = "p-cli-method-capability"
        code, out, err = self.run_cli(
            ["inspect", "https://technocore.chat/llms.txt", "--method", secret]
        )
        self.assertEqual(code, 2)
        self.assertEqual(err, "")
        self.assertEqual(json.loads(out)["method"], "<unsupported>")
        self.assertNotIn(secret, out)

    def test_parser_errors_do_not_reflect_untrusted_argument_values(self) -> None:
        secret = "p-invalid-command-capability"
        out = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), self.assertRaises(SystemExit):
            main([secret])
        self.assertNotIn(secret, out.getvalue())
        self.assertNotIn(secret, err.getvalue())

    def test_signed_private_write_is_redacted_in_stdout_stderr_and_ledger(self) -> None:
        with project_temp_dir() as directory:
            private_namespace = "mb-p-cli-private-namespace"
            private_key = "d-p-cli-private-key"
            nonce = "3141592653"
            value = "cli-private-note-value"
            query_name = "cli-private-query-name"
            query_value = "cli-private-query-value"
            url = (
                f"https://technocore.chat/kv/{private_namespace}/{private_key}/set-signed/"
                f"{DID}/{SIG}/{nonce}/{value}?{query_name}={query_value}"
            )
            ledger = directory / "ledger.jsonl"
            code, out, err = self.run_cli(["inspect", url, "--record", str(ledger)])
            self.assertEqual(code, 0, err)
            combined = out + err + ledger.read_text(encoding="utf-8")
            for secret in (
                private_namespace,
                private_key,
                DID,
                SIG,
                nonce,
                value,
                query_name,
                query_value,
                url,
                hashlib.sha256(url.encode()).hexdigest(),
            ):
                self.assertNotIn(secret, combined)

    def test_unsafe_ledger_path_is_rejected_without_reflection(self) -> None:
        with project_temp_dir() as directory:
            secret = "p-wallet-ledger-capability.jsonl"
            path = directory / secret
            code, out, err = self.run_cli(
                ["inspect", "https://technocore.chat/llms.txt", "--record", str(path)]
            )
            self.assertEqual(code, 2)
            self.assertEqual(out, "")
            self.assertNotIn(secret, err)
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
