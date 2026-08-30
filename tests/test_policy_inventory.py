from __future__ import annotations

import json
import tomllib
import unittest

from _repo_test_support import ROOT
from technocore_guard.classifier import inspect_url
from technocore_guard.models import Effect
import technocore_guard

POLICY = json.loads((ROOT / "policy" / "routes-v1.json").read_text(encoding="utf-8"))
BASELINE = json.loads((ROOT / "UPSTREAM_BASELINE.json").read_text(encoding="utf-8"))
DID = "did:key:z6Mk" + "1" * 44
SIG = "A" * 86


class PolicyInventoryTests(unittest.TestCase):
    def test_module_version_mirrors_authoritative_project_version(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        self.assertEqual(technocore_guard.__version__, project["version"])
        self.assertEqual(project["version"], "0.1.0")

    def test_baseline_and_policy_pin_the_same_source(self) -> None:
        self.assertEqual(POLICY["upstream_commit"], BASELINE["commit"])
        self.assertEqual(POLICY["official_origin"], "https://technocore.chat")
        self.assertEqual(BASELINE["repository"], "flop-labs/technocore-chat")

    def test_representative_write_inventory_stays_write(self) -> None:
        examples = [
            ("GET", "https://technocore.chat/r/lobby/say/bot/hello"),
            ("GET", f"https://technocore.chat/r/lobby/say-signed/{DID}/{SIG}/1/hello"),
            ("POST", "https://technocore.chat/r/lobby"),
            ("GET", "https://technocore.chat/kv/topic/lobby/set/hello"),
            (
                "GET",
                f"https://technocore.chat/kv/room-owners/d-demo/set-signed/{DID}/{SIG}/1/{DID}",
            ),
            ("POST", "https://technocore.chat/kv/topic/lobby"),
        ]
        self.assertEqual(len(POLICY["write_routes"]), len(examples))
        for method, url in examples:
            with self.subTest(method=method, url=url):
                self.assertEqual(inspect_url(url, method).effect, Effect.WRITE)

    def test_policy_inventory_is_exact_not_only_the_same_size(self) -> None:
        self.assertEqual(
            POLICY["write_routes"],
            [
                "GET /r/{room}/say/{nick}/{text}",
                "GET /r/{room}/say-signed/{did}/{signature}/{nonce}/{text}",
                "POST /r/{room}",
                "GET /kv/{namespace}/{key}/set/{value}",
                "GET /kv/{namespace}/{key}/set-signed/{did}/{signature}/{nonce}/{value}",
                "POST /kv/{namespace}/{key}",
            ],
        )
        self.assertEqual(
            POLICY["read_routes"],
            [
                "/",
                "/llms.txt",
                "/skill.md",
                "/patterns.md",
                "/auth.md",
                "/humans",
                "/openapi.json",
                "/.well-known/agent.json",
                "/.well-known/agent-skills/index.json",
                "/config",
                "/healthz",
                "/robots.txt",
                "/sitemap.xml",
                "/rooms",
                "/r/{room}",
                "/kv/{namespace}",
                "/kv/{namespace}/{key}",
            ],
        )

    def test_get_shaped_write_routes_do_not_widen_to_post(self) -> None:
        urls = [
            "https://technocore.chat/r/lobby/say/bot/hello",
            f"https://technocore.chat/r/lobby/say-signed/{DID}/{SIG}/1/hello",
            "https://technocore.chat/kv/topic/lobby/set/hello",
            f"https://technocore.chat/kv/topic/lobby/set-signed/{DID}/{SIG}/1/hello",
        ]
        for url in urls:
            with self.subTest(route=url.split("/")[3:6]):
                self.assertEqual(inspect_url(url, "POST").effect, Effect.UNKNOWN)

    def test_representative_read_inventory_stays_read(self) -> None:
        examples = [
            "https://technocore.chat/llms.txt",
            "https://technocore.chat/rooms",
            "https://technocore.chat/r/lobby",
            "https://technocore.chat/kv/topic",
            "https://technocore.chat/kv/topic/lobby",
        ]
        for url in examples:
            with self.subTest(url=url):
                self.assertEqual(inspect_url(url).effect, Effect.READ)


if __name__ == "__main__":
    unittest.main()
