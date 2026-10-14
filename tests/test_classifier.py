from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import replace

from _repo_test_support import ROOT  # noqa: F401 - also bootstraps the src layout.
from technocore_guard.classifier import inspect_url
from technocore_guard.models import Effect, Inspection, Risk

DID = "did:key:z6Mk" + "1" * 44
SIG = "A" * 86


class ClassifierTests(unittest.TestCase):
    def assert_effect(self, url: str, effect: Effect, *, method: str = "GET"):
        result = inspect_url(url, method)
        self.assertEqual(result.effect, effect)
        self.assertFalse(result.network_executed)
        public = json.dumps(result.to_public_dict(), ensure_ascii=False, sort_keys=True)
        self.assertNotIn(url, public)
        return result

    def test_static_document_is_read(self) -> None:
        result = self.assert_effect("https://technocore.chat/llms.txt", Effect.READ)
        self.assertEqual(result.risk, Risk.LOW)
        self.assertEqual(result.route_id, "static-document")

    def test_new_static_documents_are_reads_without_query_semantics(self) -> None:
        paths = (
            "/interop.md",
            "/.well-known/api-catalog",
            "/.well-known/ai-catalog.json",
            "/.well-known/security.txt",
        )
        for path in paths:
            with self.subTest(path=path):
                result = self.assert_effect(
                    "https://technocore.chat" + path,
                    Effect.READ,
                )
                self.assertEqual(result.route_id, "static-document")
                self.assert_effect(
                    "https://technocore.chat" + path + "?format=json",
                    Effect.UNKNOWN,
                )

    def test_mcp_server_card_is_static_read_like_other_well_known_documents(self) -> None:
        base = "https://technocore.chat"
        card = "/.well-known/mcp/server-card.json"
        for method in ("GET", "HEAD"):
            with self.subTest(method=method):
                result = self.assert_effect(base + card, Effect.READ, method=method)
                self.assertEqual(result.route_id, "static-document")
                self.assertEqual(result.risk, Risk.LOW)
                self.assertEqual(result.sanitized_target, card)
                self.assertEqual(result.origin, "https://technocore.chat")
                self.assertFalse(result.contains_private_capability)
                self.assertFalse(result.contains_user_content)
                self.assertFalse(result.contains_replay_material)

    def test_mcp_server_card_wrong_method_and_query_match_existing_static_documents(self) -> None:
        # Expectations come from the reviewed /.well-known/ai-catalog.json document
        # with the same shape, so this adds no new rule for the server card.
        base = "https://technocore.chat"
        card = "/.well-known/mcp/server-card.json"
        reference = "/.well-known/ai-catalog.json"
        cases = [(method, "") for method in ("POST", "PUT", "DELETE", "PATCH")]
        cases += [("GET", "?x=1"), ("HEAD", "?x=1"), ("GET", "?format=json")]
        for method, query in cases:
            with self.subTest(method=method, query=query):
                expected = inspect_url(base + reference + query, method)
                self.assertNotEqual(expected.effect, Effect.READ)
                result = self.assert_effect(base + card + query, expected.effect, method=method)
                self.assertEqual(result.route_id, expected.route_id)
                self.assertEqual(result.risk, expected.risk)
                self.assertEqual(result.sanitized_target, expected.sanitized_target)
                self.assertNotIn("server-card", json.dumps(result.to_public_dict()))

    def test_mcp_server_card_adversarial_spellings_are_never_reads(self) -> None:
        base = "https://technocore.chat"
        shaped = {
            "encoded-slash": (
                "/.well-known/mcp%2Fserver-card.json",
                "/.well-known%2Fai-catalog.json",
            ),
            "encoded-percent": (
                "/.well-known/mcp/server%25card.json",
                "/.well-known/ai%25catalog.json",
            ),
            "trailing-slash": (
                "/.well-known/mcp/server-card.json/",
                "/.well-known/ai-catalog.json/",
            ),
            "mixed-case": (
                "/.Well-Known/mcp/server-card.json",
                "/.Well-Known/ai-catalog.json",
            ),
        }
        for shape, (path, reference) in shaped.items():
            with self.subTest(shape=shape):
                expected = inspect_url(base + reference, "GET")
                self.assertIn(expected.effect, {Effect.BLOCKED, Effect.UNKNOWN})
                result = self.assert_effect(base + path, expected.effect)
                self.assertEqual(result.route_id, expected.route_id)
                self.assertEqual(result.sanitized_target, expected.sanitized_target)
        self.assertEqual(
            inspect_url(base + shaped["encoded-slash"][0], "GET").effect,
            Effect.BLOCKED,
        )
        self.assertEqual(
            inspect_url(base + shaped["encoded-percent"][0], "GET").effect,
            Effect.BLOCKED,
        )
        # Upstream serves only the canonical card path; these are not aliases.
        for shape, path in (
            ("plural-cards", "/.well-known/mcp/server-cards.json"),
            ("mcp-json", "/.well-known/mcp.json"),
            ("no-extension", "/.well-known/mcp/server-card"),
        ):
            for method in ("GET", "HEAD"):
                with self.subTest(shape=shape, method=method):
                    result = self.assert_effect(base + path, Effect.UNKNOWN, method=method)
                    self.assertEqual(result.route_id, "unknown-route")
                    self.assertEqual(result.sanitized_target, "<unknown-official-origin-route>")

    def test_stats_is_dedicated_token_gated_url_read(self) -> None:
        result = self.assert_effect("https://technocore.chat/stats", Effect.READ)
        self.assertEqual(result.route_id, "stats-read")
        self.assertEqual(result.risk, Risk.HIGH)
        self.assertIn("404", result.reason)
        self.assertIn("outside this URL-only inspection", result.reason)
        self.assert_effect("https://technocore.chat/stats?format=json", Effect.UNKNOWN)

    def test_events_discovery_get_and_head_are_dedicated_reads(self) -> None:
        for method in ("GET", "HEAD"):
            with self.subTest(method=method):
                result = self.assert_effect(
                    "https://technocore.chat/r/events?since=1&wait=0",
                    Effect.READ,
                    method=method,
                )
                self.assertEqual(result.route_id, "events-discovery")
                self.assertEqual(result.sanitized_target, "/r/events")
                self.assertIn("untrusted caller-chosen", result.reason)

    def test_events_post_is_reserved_replay_sensitive_write_intent(self) -> None:
        result = self.assert_effect(
            "https://technocore.chat/r/events",
            Effect.WRITE,
            method="POST",
        )
        self.assertEqual(result.route_id, "post-events-reserved")
        self.assertTrue(result.contains_user_content)
        self.assertTrue(result.contains_replay_material)
        self.assertIn("403", result.reason)

    def test_room_read_is_read(self) -> None:
        result = self.assert_effect("https://technocore.chat/r/lobby?since=2&limit=10", Effect.READ)
        self.assertEqual(result.route_id, "read-room")
        self.assertEqual(result.sanitized_target, "/r/<room>")

    def test_get_room_say_is_critical_write(self) -> None:
        url = "https://technocore.chat/r/lobby/say/example/hello%20world"
        result = self.assert_effect(url, Effect.WRITE)
        self.assertEqual(result.risk, Risk.CRITICAL)
        self.assertEqual(result.route_id, "unsigned-room-write")
        self.assertTrue(result.contains_user_content)
        self.assertEqual(result.sanitized_target, "/r/<room>/say/<nick>/<text>")
        self.assertNotIn("hello", json.dumps(result.to_public_dict()))

    def test_get_note_set_is_critical_write(self) -> None:
        url = "https://technocore.chat/kv/topic/lobby/set/hello%20agents?if_absent=1"
        result = self.assert_effect(url, Effect.WRITE)
        self.assertEqual(result.route_id, "unsigned-note-write")
        self.assertEqual(result.sanitized_target, "/kv/<namespace>/<key>/set/<value>")
        self.assertTrue(result.contains_user_content)

    def test_path_converter_write_tails_accept_literal_slashes_and_redact(self) -> None:
        secret_tail = "secret/second/private-value"
        examples = (
            (
                f"https://technocore.chat/r/lobby/say/example/{secret_tail}",
                "unsigned-room-write",
                False,
            ),
            (
                f"https://technocore.chat/r/lobby/say-signed/{DID}/{SIG}/1/{secret_tail}",
                "signed-room-write",
                True,
            ),
            (
                f"https://technocore.chat/kv/topic/state/set/{secret_tail}",
                "unsigned-note-write",
                False,
            ),
            (
                f"https://technocore.chat/kv/topic/state/set-signed/{DID}/{SIG}/1/{secret_tail}",
                "signed-note-write",
                True,
            ),
        )
        for url, route_id, replay in examples:
            with self.subTest(route_id=route_id):
                result = self.assert_effect(url, Effect.WRITE)
                rendered = json.dumps(result.to_public_dict(), sort_keys=True)
                self.assertEqual(result.route_id, route_id)
                self.assertEqual(result.risk, Risk.CRITICAL)
                self.assertEqual(result.contains_replay_material, replay)
                self.assertNotIn(secret_tail, rendered)
                self.assertNotIn("private-value", rendered)

    def test_path_converter_tails_do_not_allow_encoded_slashes(self) -> None:
        urls = (
            "https://technocore.chat/r/lobby/say/example/hello%2Fworld",
            f"https://technocore.chat/r/lobby/say-signed/{DID}/{SIG}/1/hello%2Fworld",
            "https://technocore.chat/kv/topic/state/set/hello%2Fworld",
            f"https://technocore.chat/kv/topic/state/set-signed/{DID}/{SIG}/1/hello%2Fworld",
        )
        for url in urls:
            with self.subTest(url=url):
                self.assert_effect(url, Effect.BLOCKED)

    def test_room_export_is_read_and_redacts_private_capabilities(self) -> None:
        examples = (
            ("lobby", "/r/<room>/export", Risk.MEDIUM, False),
            ("p-lobby", "/r/<private-room>/export", Risk.HIGH, True),
        )
        for room, target, risk, capability in examples:
            for method in ("GET", "HEAD"):
                with self.subTest(room=room, method=method):
                    result = self.assert_effect(
                        f"https://technocore.chat/r/{room}/export",
                        Effect.READ,
                        method=method,
                    )
                    self.assertEqual(result.route_id, "export-room")
                    self.assertEqual(result.sanitized_target, target)
                    self.assertEqual(result.risk, risk)
                    self.assertEqual(result.contains_private_capability, capability)
        self.assert_effect("https://technocore.chat/r/lobby/export?limit=1", Effect.UNKNOWN)

    def test_format_query_is_allowed_on_write_responses(self) -> None:
        examples = (
            ("GET", "https://technocore.chat/r/lobby/say/bot/hello?format=json"),
            ("GET", f"https://technocore.chat/r/lobby/say-signed/{DID}/{SIG}/1/hello?format=json"),
            ("POST", "https://technocore.chat/r/lobby?format=json"),
            ("POST", "https://technocore.chat/kv/topic/state?format=json"),
            ("GET", "https://technocore.chat/kv/topic/state/set/hello?format=json&if=old&if_absent=false"),
            ("GET", f"https://technocore.chat/kv/topic/state/set-signed/{DID}/{SIG}/1/hello?format=json&if=old&if_absent=false"),
        )
        for method, url in examples:
            with self.subTest(method=method, url=url):
                result = self.assert_effect(url, Effect.WRITE, method=method)
                self.assertEqual(result.risk, Risk.CRITICAL)
                self.assertEqual(result.warnings, ())

    def test_post_routes_are_writes_while_gets_are_reads(self) -> None:
        room = "https://technocore.chat/r/lobby"
        note = "https://technocore.chat/kv/topic/lobby"
        self.assert_effect(room, Effect.READ, method="GET")
        self.assert_effect(note, Effect.READ, method="GET")
        room_post = self.assert_effect(room, Effect.WRITE, method="POST")
        note_post = self.assert_effect(note, Effect.WRITE, method="POST")
        self.assertTrue(room_post.contains_replay_material)
        self.assertTrue(note_post.contains_replay_material)

    def test_head_write_shape_is_still_write(self) -> None:
        urls = [
            "https://technocore.chat/r/lobby/say/example/not-a-read",
            f"https://technocore.chat/r/lobby/say-signed/{DID}/{SIG}/1/not-a-read",
            "https://technocore.chat/kv/topic/key/set/not-a-read",
            f"https://technocore.chat/kv/topic/key/set-signed/{DID}/{SIG}/1/not-a-read",
        ]
        for url in urls:
            with self.subTest(route=url.split("/")[3:6]):
                result = self.assert_effect(url, Effect.WRITE, method="HEAD")
                self.assertEqual(result.risk, Risk.CRITICAL)

    def test_signed_room_write_redacts_did_signature_nonce_and_text(self) -> None:
        url = f"https://technocore.chat/r/lobby/say-signed/{DID}/{SIG}/123456/secret-message"
        result = self.assert_effect(url, Effect.WRITE)
        public = json.dumps(result.to_public_dict(), sort_keys=True)
        self.assertTrue(result.contains_replay_material)
        self.assertNotIn(DID, public)
        self.assertNotIn(SIG, public)
        self.assertNotIn("123456", public)
        self.assertNotIn("secret-message", public)
        self.assertEqual(
            result.sanitized_target,
            "/r/<room>/say-signed/<did>/<signature>/<nonce>/<text>",
        )

    def test_signed_note_write_redacts_every_sensitive_component(self) -> None:
        url = f"https://technocore.chat/kv/room-owners/d-demo/set-signed/{DID}/{SIG}/9/{DID}?if_absent=1"
        result = self.assert_effect(url, Effect.WRITE)
        public = json.dumps(result.to_public_dict(), sort_keys=True)
        self.assertEqual(result.route_id, "signed-note-write")
        self.assertNotIn(DID, public)
        self.assertNotIn(SIG, public)
        self.assertNotIn("room-owners", public)
        self.assertNotIn("d-demo", public)

    def test_private_room_capability_is_never_exposed(self) -> None:
        private = "p-quiet-capability-7x"
        url = f"https://technocore.chat/r/{private}"
        result = self.assert_effect(url, Effect.READ)
        public = json.dumps(result.to_public_dict(), sort_keys=True)
        self.assertTrue(result.contains_private_capability)
        self.assertEqual(result.risk, Risk.HIGH)
        self.assertEqual(result.sanitized_target, "/r/<private-room>")
        self.assertNotIn(private, public)

    def test_private_note_namespace_is_a_capability(self) -> None:
        private = "p-state-72dba"
        url = f"https://technocore.chat/kv/{private}/cursor"
        result = self.assert_effect(url, Effect.READ)
        public = json.dumps(result.to_public_dict(), sort_keys=True)
        self.assertTrue(result.contains_private_capability)
        self.assertEqual(result.risk, Risk.HIGH)
        self.assertEqual(result.sanitized_target, "/kv/<private-namespace>/<key>")
        self.assertNotIn(private, public)

    def test_private_note_key_is_a_capability(self) -> None:
        private = "p-secret-key"
        url = f"https://technocore.chat/kv/state/{private}"
        result = self.assert_effect(url, Effect.READ)
        self.assertTrue(result.contains_private_capability)
        self.assertEqual(result.sanitized_target, "/kv/<namespace>/<private-key>")

    def test_stacked_private_capability_prefixes_are_always_redacted(self) -> None:
        for private in ("mb-p-room-secret", "d-p-note-secret", "e-mb-p-stacked-secret"):
            urls = [
                f"https://technocore.chat/r/{private}",
                f"https://technocore.chat/kv/{private}/cursor",
                f"https://technocore.chat/kv/state/{private}",
            ]
            for url in urls:
                with self.subTest(shape=url.count("/")):
                    result = inspect_url(url)
                    rendered = json.dumps(result.to_public_dict(), sort_keys=True)
                    self.assertTrue(result.contains_private_capability)
                    self.assertNotIn(private, rendered)

    def test_duplicate_and_conflicting_conditionals_raise_generic_warnings(self) -> None:
        url = "https://technocore.chat/kv/topic/lobby/set/x?if=old&if_absent=1&if=again"
        result = self.assert_effect(url, Effect.WRITE)
        self.assertEqual(result.risk, Risk.CRITICAL)
        self.assertIn("one or more duplicate query parameters are present", result.warnings)
        self.assertIn("conflicting conditional query parameters are present", result.warnings)
        rendered = json.dumps(result.to_public_dict(), sort_keys=True)
        self.assertNotIn("old", rendered)
        self.assertNotIn("again", rendered)

    def test_if_absent_semantics_match_upstream_exactly(self) -> None:
        base = "https://technocore.chat/kv/topic/lobby/set/x?if=old&if_absent="
        for value in ("1", "true", "TRUE", "yes", "no", "off", "sometimes"):
            with self.subTest(truthy=value):
                result = self.assert_effect(base + value, Effect.WRITE)
                self.assertIn("conflicting conditional query parameters are present", result.warnings)
        for value in ("", "0", "false"):
            with self.subTest(false=value):
                result = self.assert_effect(base + value, Effect.WRITE)
                self.assertNotIn("conflicting conditional query parameters are present", result.warnings)

    def test_duplicate_if_absent_uses_last_value_for_conflict_parity(self) -> None:
        base = "https://technocore.chat/kv/topic/lobby/set/x?if=old"
        last_false = self.assert_effect(base + "&if_absent=1&if_absent=0", Effect.WRITE)
        self.assertIn("one or more duplicate query parameters are present", last_false.warnings)
        self.assertNotIn("conflicting conditional query parameters are present", last_false.warnings)

        last_true = self.assert_effect(base + "&if_absent=0&if_absent=FALSE", Effect.WRITE)
        self.assertIn("one or more duplicate query parameters are present", last_true.warnings)
        self.assertIn("conflicting conditional query parameters are present", last_true.warnings)

    def test_duplicate_or_route_specific_query_misuse_makes_reads_unknown(self) -> None:
        urls = (
            "https://technocore.chat/rooms?since=1",
            "https://technocore.chat/rooms?limit=1&limit=2",
            "https://technocore.chat/r/lobby?since=1&since=2",
            "https://technocore.chat/kv/topic?limit=1",
            "https://technocore.chat/kv/topic/key?since=1",
        )
        for url in urls:
            with self.subTest(url=url):
                self.assert_effect(url, Effect.UNKNOWN)

    def test_query_anomalies_never_downgrade_known_writes(self) -> None:
        examples = (
            ("GET", "https://technocore.chat/r/lobby/say/bot/x?format=json&format=text"),
            ("POST", "https://technocore.chat/r/lobby?since=1&since=2"),
            ("POST", "https://technocore.chat/r/events?format=json"),
            ("GET", "https://technocore.chat/kv/topic/key/set/x?unknown=1"),
            ("POST", "https://technocore.chat/kv/topic/key?if_absent=maybe"),
        )
        for method, url in examples:
            with self.subTest(method=method, url=url):
                result = self.assert_effect(url, Effect.WRITE, method=method)
                self.assertEqual(result.risk, Risk.CRITICAL)

    def test_unknown_query_name_is_not_echoed(self) -> None:
        query_name = "secret-action-parameter"
        url = f"https://technocore.chat/llms.txt?{query_name}=open"
        result = self.assert_effect(url, Effect.UNKNOWN)
        public = json.dumps(result.to_public_dict(), sort_keys=True)
        self.assertEqual(result.risk, Risk.HIGH)
        self.assertNotIn(query_name, public)
        self.assertEqual(result.route_id, "unknown-route")
        self.assertEqual(result.warnings, ())

    def test_unknown_query_does_not_hide_a_known_write_shape(self) -> None:
        url = "https://technocore.chat/r/lobby/say/example/content?unreviewed=value"
        result = self.assert_effect(url, Effect.WRITE)
        self.assertEqual(result.risk, Risk.CRITICAL)
        self.assertEqual(result.route_id, "unsigned-room-write")

    def test_unknown_faucet_route_fails_closed(self) -> None:
        result = self.assert_effect("https://technocore.chat/faucet", Effect.UNKNOWN)
        self.assertEqual(result.risk, Risk.HIGH)
        self.assertEqual(result.sanitized_target, "<unknown-official-origin-route>")

    def test_unknown_private_looking_route_does_not_echo_it(self) -> None:
        private = "p-unknown-route-capability"
        url = f"https://technocore.chat/unreviewed/{private}"
        result = self.assert_effect(url, Effect.UNKNOWN)
        rendered = json.dumps(result.to_public_dict(), sort_keys=True)
        self.assertNotIn(private, rendered)
        self.assertNotIn(hashlib.sha256(url.encode()).hexdigest(), rendered)

    def test_room_named_faucet_is_only_a_room_read(self) -> None:
        result = self.assert_effect("https://technocore.chat/r/faucet", Effect.READ)
        self.assertEqual(result.route_id, "read-room")

    def test_wrong_or_disguised_hosts_are_blocked(self) -> None:
        urls = [
            "http://technocore.chat/llms.txt",
            "HTTPS://technocore.chat/llms.txt",
            "https://TECHNOCORE.CHAT/llms.txt",
            "https://technocore.chat.evil.example/llms.txt",
            "https://technocore.chat@evil.example/llms.txt",
            "https://evil.example@technocore.chat/llms.txt",
            "https://technocore.chat.:443/llms.txt",
            "https://technocore.chat./llms.txt",
            "https://technocore.chat:443/llms.txt",
            "https://technoсore.chat/llms.txt",  # Cyrillic small es.
        ]
        for url in urls:
            with self.subTest(url=url):
                self.assert_effect(url, Effect.BLOCKED)

    def test_encoded_delimiters_controls_double_encoding_and_dot_segments_are_blocked(self) -> None:
        urls = [
            "https://technocore.chat/r/lobby%2Fsay/example/hello",
            "https://technocore.chat/r/lobby%3Fsay/example/hello",
            "https://technocore.chat/r/lobby%23say/example/hello",
            "https://technocore.chat/r/lobby%5Csay/example/hello",
            "https://technocore.chat/r/lobby%25say/example/hello",
            "https://technocore.chat/r/lobby?x=%23fragment",
            "https://technocore.chat/r/lobby?x=%5Cescape",
            "https://technocore.chat/r/lobby?x=%0Aline",
            "https://technocore.chat/r/lobby/say/example/%C2%85",
            "https://technocore.chat/r/lobby/say/example/%E2%80%8B",
            "https://technocore.chat/r/%252e%252e/x",
            "https://technocore.chat/r/%2e%2e/x",
            "https://technocore.chat/r/../x",
            "https://technocore.chat/r/.%2e/x",
            "https://technocore.chat/r/%2E./x",
            "https://technocore.chat/r/lobby#ignored",
            "https://technocore.chat/llms.txt#",
            "https://technocore.chat\\evil.example/llms.txt",
        ]
        for url in urls:
            with self.subTest(url=url):
                self.assert_effect(url, Effect.BLOCKED)

    def test_invisible_and_surrounding_whitespace_are_blocked(self) -> None:
        urls = [
            " https://technocore.chat/llms.txt",
            "https://technocore.chat/llms.txt ",
            "https://technocore.chat/r/lobby/say/example/hello world",
            "https://technocore.chat/r/lobby?format=json\tmore",
            "https://technocore.chat/llms.txt\u200b",
            "https://technocore.chat/llms.txt\n",
        ]
        for url in urls:
            with self.subTest(url=url):
                self.assert_effect(url, Effect.BLOCKED)

    def test_malformed_signed_material_is_unknown_not_partially_trusted(self) -> None:
        uppercase_did = f"DID:key:z6Mk{'1' * 44}"
        bad_sig = "A" * 85 + "B"
        urls = [
            f"https://technocore.chat/r/lobby/say-signed/{uppercase_did}/{SIG}/1/x",
            f"https://technocore.chat/r/lobby/say-signed/{DID}/{bad_sig}/1/x",
            f"https://technocore.chat/r/lobby/say-signed/{DID}/{SIG}/١/x",
        ]
        for url in urls:
            with self.subTest(url=url):
                self.assert_effect(url, Effect.UNKNOWN)

    def test_public_result_has_neither_raw_url_nor_deterministic_input_hash(self) -> None:
        private = "p-guessable-123"
        url = f"https://technocore.chat/r/{private}"
        result = self.assert_effect(url, Effect.READ)
        payload = result.to_public_dict()
        rendered = json.dumps(payload, sort_keys=True)
        self.assertNotIn(private, rendered)
        self.assertNotIn(hashlib.sha256(url.encode()).hexdigest(), rendered)
        self.assertNotIn("input_sha256", payload)
        self.assertNotIn("raw_url", payload)

    def test_unsupported_method_is_exactly_rejected_without_reflection(self) -> None:
        secret = "p-method-capability-never-reflect"
        for method in ("get", " GET ", secret):
            with self.subTest(kind="noncanonical-method"):
                result = inspect_url("https://technocore.chat/llms.txt", method)
                rendered = json.dumps(result.to_public_dict(), sort_keys=True)
                self.assertEqual(result.effect, Effect.BLOCKED)
                self.assertEqual(result.method, "<unsupported>")
                self.assertNotIn(secret, rendered)

    def test_public_serialization_rejects_caller_constructed_free_text(self) -> None:
        secret = "p-injected-public-field-never-store"
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
        with self.assertRaises(ValueError) as captured:
            forged.to_public_dict()
        self.assertNotIn(secret, str(captured.exception))

    def test_public_serialization_rejects_risk_downgrades(self) -> None:
        private = inspect_url("https://technocore.chat/r/p-risk-downgrade-secret")
        forged = replace(private, risk=Risk.LOW)
        with self.assertRaises(ValueError):
            forged.to_public_dict()


if __name__ == "__main__":
    unittest.main()
