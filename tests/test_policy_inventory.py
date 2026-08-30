from __future__ import annotations

import json
import tomllib
import unittest

from _repo_test_support import ROOT
from technocore_guard import classifier
from technocore_guard.classifier import inspect_url
from technocore_guard.models import Effect
import technocore_guard

POLICY = json.loads((ROOT / "policy" / "routes-v2.json").read_text(encoding="utf-8"))
BASELINE = json.loads((ROOT / "UPSTREAM_BASELINE.json").read_text(encoding="utf-8"))
UPSTREAM = json.loads(
    (ROOT / "tests" / "fixtures" / "upstream-routes-7707cb63.json").read_text(encoding="utf-8")
)
DID = "did:key:z6Mk" + "1" * 44
SIG = "A" * 86


def _example(path: str) -> str:
    replacements = {
        "{room}": "lobby",
        "{nick}": "bot",
        "{text:path}": "hello",
        "{ns}": "topic",
        "{key}": "state",
        "{value:path}": "value",
        "{did}": DID,
        "{sig}": SIG,
        "{nonce}": "1",
    }
    for old, new in replacements.items():
        path = path.replace(old, new)
    return "https://technocore.chat" + path


def _upstream_covers(policy_path: str, upstream_path: str) -> bool:
    if policy_path == upstream_path:
        return True
    return policy_path == "/r/events" and upstream_path == "/r/{room}"


class PolicyInventoryTests(unittest.TestCase):
    def test_module_version_mirrors_authoritative_project_version(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        self.assertEqual(technocore_guard.__version__, project["version"])
        self.assertEqual(project["version"], "0.2.0")

    def test_baseline_policy_and_offline_fixture_pin_same_source(self) -> None:
        self.assertEqual(POLICY["reviewed_upstream_commit"], BASELINE["commit"])
        self.assertEqual(UPSTREAM["commit"], BASELINE["commit"])
        self.assertEqual(POLICY["reviewed_upstream_version"], BASELINE["version"])
        self.assertEqual(UPSTREAM["version"], BASELINE["version"])
        self.assertEqual(POLICY["official_origin"], "https://technocore.chat")
        self.assertEqual(BASELINE["repository"], "flop-labs/technocore-chat")

    def test_effect_taxonomy_is_explicit_and_complete(self) -> None:
        self.assertEqual(set(POLICY["effect_taxonomy"]), {item.value for item in Effect})

    def test_policy_entries_match_runtime_classification(self) -> None:
        for route in POLICY["routes"]:
            for method in route["methods"]:
                with self.subTest(route=route["route_id"], method=method):
                    example_url = _example(route["path_template"])
                    result = inspect_url(example_url, method)
                    self.assertEqual(result.route_id, route["route_id"])
                    self.assertEqual(result.effect.value, route["effect"])
                    self.assertIn(result.sanitized_target, route["sanitized_targets"])
                    runtime_route = classifier._classify_route(
                        example_url.removeprefix("https://technocore.chat"),
                        method,
                    )
                    self.assertIsNotNone(runtime_route)
                    self.assertEqual(
                        runtime_route.allowed_query_keys,
                        frozenset(route["allowed_query_keys"]),
                    )
                    for key in route["allowed_query_keys"]:
                        queried = inspect_url(_example(route["path_template"]) + f"?{key}=0", method)
                        self.assertEqual(queried.route_id, route["route_id"])
                        self.assertEqual(queried.effect.value, route["effect"])

    def test_every_sanitized_target_is_reachable(self) -> None:
        private_variants = [
            ("{room}", "p-room"),
            ("{ns}", "p-namespace"),
            ("{key}", "p-key"),
        ]
        for route in POLICY["routes"]:
            reached = set()
            candidates = [route["path_template"]]
            for marker, value in private_variants:
                candidates += [path.replace(marker, value) for path in list(candidates) if marker in path]
            for path in candidates:
                for method in route["methods"]:
                    result = inspect_url(_example(path), method)
                    if result.route_id == route["route_id"]:
                        reached.add(result.sanitized_target)
            self.assertEqual(reached, set(route["sanitized_targets"]), route["route_id"])

    def test_offline_upstream_inventory_is_covered_by_policy(self) -> None:
        policy_routes = POLICY["routes"]
        for upstream_path, upstream_methods in UPSTREAM["routes"]:
            for method in upstream_methods:
                matches = [
                    route
                    for route in policy_routes
                    if _upstream_covers(route["path_template"], upstream_path)
                    and method in route["methods"]
                ]
                self.assertTrue(matches, f"uncovered reviewed route: {method} {upstream_path}")

    def test_every_policy_route_comes_from_reviewed_upstream_inventory(self) -> None:
        for route in POLICY["routes"]:
            matches = [
                (path, methods)
                for path, methods in UPSTREAM["routes"]
                if _upstream_covers(route["path_template"], path)
            ]
            self.assertTrue(matches, route["path_template"])
            upstream_methods = set().union(*(set(methods) for _, methods in matches))
            # HEAD on GET-shaped mutations is an intentional fail-closed classifier
            # extension even though current upstream explicitly removes HEAD.
            methods = set(route["methods"])
            if route["effect"] == "write":
                methods.discard("HEAD")
            self.assertLessEqual(methods, upstream_methods)

    def test_get_shaped_write_routes_do_not_widen_to_post(self) -> None:
        paths = [
            "/r/lobby/say/bot/hello",
            f"/r/lobby/say-signed/{DID}/{SIG}/1/hello",
            "/kv/topic/state/set/hello",
            f"/kv/topic/state/set-signed/{DID}/{SIG}/1/hello",
        ]
        for path in paths:
            with self.subTest(path=path):
                self.assertEqual(
                    inspect_url("https://technocore.chat" + path, "POST").effect,
                    Effect.UNKNOWN,
                )


if __name__ == "__main__":
    unittest.main()