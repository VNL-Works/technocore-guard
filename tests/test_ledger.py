from __future__ import annotations

import hashlib
import json
import unittest
from unittest import mock

from _repo_test_support import project_temp_dir
from technocore_guard.classifier import inspect_url
import technocore_guard.ledger as ledger_module
from technocore_guard.ledger import LedgerError, _hash, append_inspection, verify_ledger
from technocore_guard.models import Effect, Inspection, Risk


class LedgerTests(unittest.TestCase):
    @staticmethod
    def _windows_sharing_violation() -> PermissionError:
        error = PermissionError(13, "synthetic sharing violation")
        error.winerror = 32
        return error

    def test_append_and_verify_two_redacted_records(self) -> None:
        with project_temp_dir() as directory:
            path = directory / "ledger.jsonl"
            private = "p-private-capability"
            first = inspect_url(f"https://technocore.chat/r/{private}")
            second = inspect_url("https://technocore.chat/llms.txt")
            append_inspection(path, first, created_at="2026-08-29T00:00:00+00:00")
            append_inspection(path, second, created_at="2026-08-29T00:00:01+00:00")
            state = verify_ledger(path)
            self.assertEqual(state["records"], 2)
            self.assertTrue(state["valid"])
            stored = path.read_text(encoding="utf-8")
            self.assertNotIn(private, stored)
            self.assertNotIn(f"https://technocore.chat/r/{private}", stored)

    def test_tamper_is_detected(self) -> None:
        with project_temp_dir() as directory:
            path = directory / "ledger.jsonl"
            append_inspection(path, inspect_url("https://technocore.chat/llms.txt"))
            record = json.loads(path.read_text(encoding="utf-8"))
            record["event"]["risk"] = "critical"
            path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            with self.assertRaises(LedgerError):
                verify_ledger(path)

    def test_append_refuses_corrupted_chain_without_modifying_file(self) -> None:
        with project_temp_dir() as directory:
            path = directory / "ledger.jsonl"
            append_inspection(path, inspect_url("https://technocore.chat/llms.txt"))
            original = path.read_bytes()
            path.write_bytes(original.replace(b'"risk": "low"', b'"risk": "high"'))
            corrupted = path.read_bytes()
            with self.assertRaises(LedgerError):
                append_inspection(path, inspect_url("https://technocore.chat/healthz"))
            self.assertEqual(path.read_bytes(), corrupted)

    def test_blank_line_and_non_object_are_rejected(self) -> None:
        with project_temp_dir() as directory:
            path = directory / "ledger.jsonl"
            path.write_text("\n", encoding="utf-8")
            with self.assertRaises(LedgerError):
                verify_ledger(path)
            path.write_text("[]\n", encoding="utf-8")
            with self.assertRaises(LedgerError):
                verify_ledger(path)

    def test_symlinked_parent_and_identity_directory_are_rejected(self) -> None:
        with project_temp_dir() as root:
            real = root / "real"
            real.mkdir()
            link = root / "link"
            try:
                link.symlink_to(real, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symlink creation is unavailable: {exc}")
            with self.assertRaises(LedgerError):
                append_inspection(link / "ledger.jsonl", inspect_url("https://technocore.chat/llms.txt"))
            with self.assertRaises(LedgerError):
                append_inspection(root / ".secrets" / "ledger.jsonl", inspect_url("https://technocore.chat/llms.txt"))

    def test_windows_reparse_attribute_is_treated_as_link_like(self) -> None:
        synthetic = type("SyntheticStat", (), {"st_file_attributes": 0x0400})()
        with (
            mock.patch.object(ledger_module.Path, "is_symlink", return_value=False),
            mock.patch.object(ledger_module.Path, "is_junction", return_value=False, create=True),
            mock.patch.object(ledger_module.os, "lstat", return_value=synthetic),
        ):
            self.assertTrue(ledger_module._is_link_like(ledger_module.Path("synthetic")))

    def test_credential_shaped_paths_are_rejected_before_read_or_write(self) -> None:
        with project_temp_dir() as root:
            relative_paths = (
                ".env",
                ".ssh/id_ed25519",
                "id_ed25519",
                ".aws/credentials",
                ".codex/auth.json",
                ".claude/.credentials.json",
                ".config/gh/hosts.yml",
                ".npmrc",
                ".netrc",
                "wallet.json",
                "operator_seed.txt",
                "api_key.txt",
                "access_token.txt",
                "private.pem",
                "client_secret.json",
            )
            for relative in relative_paths:
                path = root / relative
                with self.subTest(suffix=path.suffix):
                    with self.assertRaises(LedgerError) as append_error:
                        append_inspection(path, inspect_url("https://technocore.chat/llms.txt"))
                    with self.assertRaises(LedgerError) as verify_error:
                        verify_ledger(path)
                    self.assertFalse(path.exists())
                    self.assertNotIn(relative, str(append_error.exception))
                    self.assertNotIn(relative, str(verify_error.exception))

    def test_deletion_and_reordering_are_detected(self) -> None:
        with project_temp_dir() as directory:
            path = directory / "ledger.jsonl"
            for suffix in ("llms.txt", "healthz", "config"):
                append_inspection(path, inspect_url(f"https://technocore.chat/{suffix}"))
            lines = path.read_text(encoding="utf-8").splitlines()
            path.write_text("\n".join([lines[1], lines[0], lines[2]]) + "\n", encoding="utf-8")
            with self.assertRaises(LedgerError):
                verify_ledger(path)
            path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")
            with self.assertRaises(LedgerError):
                verify_ledger(path)

    def test_insertion_wrong_previous_hash_and_noncontiguous_seq_are_detected(self) -> None:
        with project_temp_dir() as directory:
            path = directory / "ledger.jsonl"
            for suffix in ("llms.txt", "healthz", "config"):
                append_inspection(path, inspect_url(f"https://technocore.chat/{suffix}"))
            originals = path.read_text(encoding="utf-8").splitlines()

            path.write_text("\n".join([originals[0], originals[0], *originals[1:]]) + "\n", encoding="utf-8")
            with self.assertRaises(LedgerError):
                verify_ledger(path)

            records = [json.loads(line) for line in originals]
            records[1]["previous_record_sha256"] = "f" * 64
            path.write_text("\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8")
            with self.assertRaises(LedgerError):
                verify_ledger(path)

            records = [json.loads(line) for line in originals]
            records[1]["seq"] = 7
            path.write_text("\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8")
            with self.assertRaises(LedgerError):
                verify_ledger(path)

    def test_malformed_nonfinite_duplicate_and_boolean_sequence_are_rejected(self) -> None:
        with project_temp_dir() as directory:
            path = directory / "ledger.jsonl"
            malformed_lines = [
                "{not-json}\n",
                '{"schema": NaN}\n',
            ]
            for line in malformed_lines:
                path.write_text(line, encoding="utf-8")
                with self.subTest(kind="malformed-ledger"):
                    with self.assertRaises(LedgerError):
                        verify_ledger(path)

            path = directory / "valid-ledger.jsonl"
            append_inspection(path, inspect_url("https://technocore.chat/llms.txt"))
            valid = path.read_text(encoding="utf-8").strip()
            duplicate = valid.replace(
                '"event": {',
                '"event": {"raw_url": "p-duplicate-key-secret"}, "event": {',
                1,
            )
            path.write_text(duplicate + "\n", encoding="utf-8")
            with self.assertRaises(LedgerError):
                verify_ledger(path)

            record = json.loads(valid)
            record["seq"] = True
            unsigned = dict(record)
            unsigned.pop("record_sha256")
            record["record_sha256"] = _hash(unsigned)
            path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            with self.assertRaises(LedgerError):
                verify_ledger(path)

    def test_rehashed_event_with_sensitive_or_extra_fields_is_rejected(self) -> None:
        with project_temp_dir() as directory:
            path = directory / "ledger.jsonl"
            append_inspection(path, inspect_url("https://technocore.chat/llms.txt"))
            record = json.loads(path.read_text(encoding="utf-8"))
            record["event"]["raw_url"] = "https://technocore.chat/r/p-forged-secret"
            record["event_sha256"] = _hash(record["event"])
            unsigned = dict(record)
            unsigned.pop("record_sha256")
            record["record_sha256"] = _hash(unsigned)
            path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            with self.assertRaises(LedgerError):
                verify_ledger(path)

    def test_created_at_cannot_be_used_as_a_free_text_channel(self) -> None:
        with project_temp_dir() as directory:
            path = directory / "ledger.jsonl"
            secret = "p-timestamp-channel-secret"
            with self.assertRaises(LedgerError) as captured:
                append_inspection(
                    path,
                    inspect_url("https://technocore.chat/llms.txt"),
                    created_at=secret,
                )
            self.assertFalse(path.exists())
            self.assertNotIn(secret, str(captured.exception))

    def test_forged_inspection_cannot_write_free_text_to_ledger(self) -> None:
        with project_temp_dir() as directory:
            path = directory / "ledger.jsonl"
            secret = "p-forged-inspection-secret"
            forged = Inspection(
                schema="technocore-guard-inspection-v1",
                method="GET",
                origin="https://technocore.chat",
                effect=Effect.READ,
                risk=Risk.LOW,
                route_id="static-document",
                sanitized_target=secret,
                reason=secret,
            )
            with self.assertRaises(LedgerError) as captured:
                append_inspection(path, forged)
            self.assertFalse(path.exists())
            self.assertNotIn(secret, str(captured.exception))

    def test_distinct_private_inputs_have_identical_redacted_event_hashes(self) -> None:
        with project_temp_dir() as directory:
            created_at = "2026-08-29T00:00:00+00:00"
            urls = [
                "https://technocore.chat/r/p-first-private-capability",
                "https://technocore.chat/r/p-second-private-capability",
            ]
            records = []
            stored = []
            for index, url in enumerate(urls):
                path = directory / f"ledger-{index}.jsonl"
                records.append(append_inspection(path, inspect_url(url), created_at=created_at))
                stored.append(path.read_text(encoding="utf-8"))
            self.assertEqual(records[0]["event_sha256"], records[1]["event_sha256"])
            self.assertEqual(records[0]["record_sha256"], records[1]["record_sha256"])
            for url, text in zip(urls, stored, strict=True):
                self.assertNotIn(url, text)
                self.assertNotIn(hashlib.sha256(url.encode()).hexdigest(), text)

    def test_every_corruption_shape_refuses_append_without_modifying_bytes(self) -> None:
        with project_temp_dir() as directory:
            path = directory / "ledger.jsonl"
            for suffix in ("llms.txt", "healthz", "config"):
                append_inspection(path, inspect_url(f"https://technocore.chat/{suffix}"))
            lines = path.read_text(encoding="utf-8").splitlines()
            second = json.loads(lines[1])
            second["previous_record_sha256"] = "f" * 64
            wrong_previous = [lines[0], json.dumps(second), lines[2]]
            second = json.loads(lines[1])
            second["seq"] = 9
            noncontiguous = [lines[0], json.dumps(second), lines[2]]
            duplicate_key = lines[0].replace(
                '"event": {',
                '"event": {"raw_url": "p-discarded-secret"}, "event": {',
                1,
            )
            corruptions = [
                "\n".join(lines) + "\n\n",
                "\n".join([lines[0], "{not-json}", lines[2]]) + "\n",
                "\n".join([lines[0], lines[0], *lines[1:]]) + "\n",
                "\n".join([lines[0], lines[2]]) + "\n",
                "\n".join([lines[1], lines[0], lines[2]]) + "\n",
                "\n".join(wrong_previous) + "\n",
                "\n".join(noncontiguous) + "\n",
                duplicate_key + "\n",
            ]
            for corrupted_text in corruptions:
                path.write_text(corrupted_text, encoding="utf-8")
                before = path.read_bytes()
                with self.subTest(bytes=len(before)):
                    with self.assertRaises(LedgerError):
                        append_inspection(path, inspect_url("https://technocore.chat/robots.txt"))
                    self.assertEqual(path.read_bytes(), before)

    def test_atomic_replace_retries_a_transient_windows_sharing_violation(self) -> None:
        with project_temp_dir() as directory:
            path = directory / "ledger.jsonl"
            real_replace = ledger_module.os.replace
            replace_calls = 0

            def transient_replace(source: str, destination: str) -> None:
                nonlocal replace_calls
                replace_calls += 1
                if replace_calls == 1:
                    raise self._windows_sharing_violation()
                real_replace(source, destination)

            with (
                mock.patch.object(ledger_module.os, "replace", side_effect=transient_replace),
                mock.patch.object(ledger_module.time, "sleep") as sleep,
            ):
                append_inspection(path, inspect_url("https://technocore.chat/llms.txt"))

            self.assertEqual(replace_calls, 2)
            sleep.assert_called_once()
            self.assertTrue(verify_ledger(path)["valid"])

    def test_persistent_windows_sharing_violation_is_bounded_and_cleans_up(self) -> None:
        with project_temp_dir() as directory:
            path = directory / "ledger.jsonl"
            append_inspection(path, inspect_url("https://technocore.chat/llms.txt"))
            before = path.read_bytes()
            real_unlink = ledger_module.os.unlink
            unlink_calls = 0

            def persistent_replace(_source: str, _destination: str) -> None:
                raise self._windows_sharing_violation()

            def transient_unlink(target: str) -> None:
                nonlocal unlink_calls
                unlink_calls += 1
                if unlink_calls == 1:
                    raise self._windows_sharing_violation()
                real_unlink(target)

            with (
                mock.patch.object(ledger_module.os, "replace", side_effect=persistent_replace) as replace,
                mock.patch.object(ledger_module.os, "unlink", side_effect=transient_unlink),
                mock.patch.object(ledger_module.time, "sleep"),
            ):
                with self.assertRaises(LedgerError) as captured:
                    append_inspection(path, inspect_url("https://technocore.chat/healthz"))

            self.assertEqual(str(captured.exception), "local ledger write failed")
            self.assertEqual(replace.call_count, len(ledger_module.WINDOWS_SHARING_RETRY_DELAYS) + 1)
            self.assertGreaterEqual(unlink_calls, 2)
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(list(directory.glob(f".{path.name}.*")), [])


if __name__ == "__main__":
    unittest.main()
