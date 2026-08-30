from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Mapping


class Effect(StrEnum):
    READ = "read"
    WRITE = "write"
    UNKNOWN = "unknown"
    BLOCKED = "blocked"


class Risk(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


PUBLIC_EVENT_FIELDS = (
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
)

_SCHEMA = "technocore-guard-inspection-v1"
_OFFICIAL_ORIGIN = "https://technocore.chat"
_SUPPORTED_METHODS = frozenset({"GET", "HEAD", "POST"})
_PUBLIC_METHODS = _SUPPORTED_METHODS | {"<unsupported>"}
_QUERY_REVIEW_SUFFIX = " Query anomalies require human review."
_WARNING_VALUES = frozenset(
    {
        "one or more duplicate query parameters are present",
        "one or more unknown query parameters are present",
        "conflicting conditional query parameters are present",
    }
)

_STATIC_TARGETS = frozenset(
    {
        "/",
        "/llms.txt",
        "/skill.md",
        "/patterns.md",
        "/interop.md",
        "/auth.md",
        "/humans",
        "/openapi.json",
        "/.well-known/agent.json",
        "/.well-known/api-catalog",
        "/.well-known/agent-skills/index.json",
        "/.well-known/ai-catalog.json",
        "/.well-known/security.txt",
        "/config",
        "/healthz",
        "/robots.txt",
        "/sitemap.xml",
    }
)

_ROUTE_TARGETS: dict[str, frozenset[str]] = {
    "static-document": _STATIC_TARGETS,
    "stats-read": frozenset({"/stats"}),
    "events-discovery": frozenset({"/r/events"}),
    "post-events-reserved": frozenset({"/r/events"}),
    "list-rooms": frozenset({"/rooms"}),
    "read-room": frozenset({"/r/<room>", "/r/<private-room>"}),
    "post-room": frozenset({"/r/<room>", "/r/<private-room>"}),
    "unsigned-room-write": frozenset(
        {"/r/<room>/say/<nick>/<text>", "/r/<private-room>/say/<nick>/<text>"}
    ),
    "signed-room-write": frozenset(
        {
            "/r/<room>/say-signed/<did>/<signature>/<nonce>/<text>",
            "/r/<private-room>/say-signed/<did>/<signature>/<nonce>/<text>",
        }
    ),
    "list-notes": frozenset({"/kv/<namespace>", "/kv/<private-namespace>"}),
    "read-note": frozenset(
        {
            "/kv/<namespace>/<key>",
            "/kv/<private-namespace>/<key>",
            "/kv/<namespace>/<private-key>",
            "/kv/<private-namespace>/<private-key>",
        }
    ),
    "post-note": frozenset(
        {
            "/kv/<namespace>/<key>",
            "/kv/<private-namespace>/<key>",
            "/kv/<namespace>/<private-key>",
            "/kv/<private-namespace>/<private-key>",
        }
    ),
    "unsigned-note-write": frozenset(
        {
            "/kv/<namespace>/<key>/set/<value>",
            "/kv/<private-namespace>/<key>/set/<value>",
            "/kv/<namespace>/<private-key>/set/<value>",
            "/kv/<private-namespace>/<private-key>/set/<value>",
        }
    ),
    "signed-note-write": frozenset(
        {
            "/kv/<namespace>/<key>/set-signed/<did>/<signature>/<nonce>/<value>",
            "/kv/<private-namespace>/<key>/set-signed/<did>/<signature>/<nonce>/<value>",
            "/kv/<namespace>/<private-key>/set-signed/<did>/<signature>/<nonce>/<value>",
            "/kv/<private-namespace>/<private-key>/set-signed/<did>/<signature>/<nonce>/<value>",
        }
    ),
    "unknown-route": frozenset({"<unknown-official-origin-route>"}),
}

_BLOCKED_REASONS: dict[str, frozenset[str]] = {
    "unsupported-method": frozenset({"Only GET, HEAD, and POST are modelled."}),
    "surrounding-whitespace": frozenset({"URL has leading or trailing whitespace."}),
    "raw-whitespace": frozenset({"Raw whitespace makes URL interpretation non-canonical."}),
    "invisible-character": frozenset(
        {"URL contains control, format, surrogate, private-use, or line-separator characters."}
    ),
    "backslash": frozenset({"Backslashes make authority and path interpretation ambiguous."}),
    "url-too-long": frozenset({"URL exceeds the conservative 16 KiB inspection ceiling."}),
    "parse-error": frozenset({"URL parser rejected the authority or port."}),
    "scheme": frozenset({"Only canonical lowercase HTTPS is accepted."}),
    "missing-authority": frozenset({"Absolute official-origin URL required."}),
    "userinfo": frozenset({"Userinfo can disguise the actual destination host."}),
    "port": frozenset({"Invalid port.", "Explicit ports are non-canonical and rejected."}),
    "fragment": frozenset({"Fragments are rejected even when empty."}),
    "missing-host": frozenset({"Host is missing."}),
    "host-spelling": frozenset({"Trailing-dot and percent-encoded host spellings are rejected."}),
    "host-idna": frozenset({"Host cannot be converted to a canonical IDNA spelling."}),
    "host": frozenset({"Destination is not the exact official Technocore host."}),
    "authority-spelling": frozenset(
        {"Authority must be exactly technocore.chat with no aliases."}
    ),
    "bad-percent-escape": frozenset({"Malformed percent escape."}),
    "encoded-control": frozenset({"Percent-encoded control characters are rejected."}),
    "encoded-delimiter": frozenset(
        {"Encoded routing delimiters or percent signs are ambiguous and rejected."}
    ),
    "path-encoding": frozenset({"Path is not valid UTF-8 after percent-decoding."}),
    "decoded-invisible": frozenset(
        {"Decoded path contains control, format, surrogate, private-use, or separator characters."}
    ),
    "double-encoding": frozenset({"A second decoding pass changes the path."}),
    "dot-segment": frozenset({"Dot segments are not valid Technocore names."}),
    "query-encoding": frozenset(
        {"Query cannot be parsed safely or contains invisible characters."}
    ),
}

_ROUTE_REASONS: dict[str, frozenset[str]] = {
    "static-document": frozenset(
        {"Official-origin static or status document; this tool still does not fetch it."}
    ),
    "stats-read": frozenset(
        {
            "Token-gated aggregate read; without the required header the server returns 404. "
            "Headers are outside this URL-only inspection."
        }
    ),
    "events-discovery": frozenset(
        {
            "Reads the server-written discovery log; announced room names are "
            "untrusted caller-chosen data."
        }
    ),
    "post-events-reserved": frozenset(
        {
            "State-changing intent targets the server-written discovery log; "
            "the current server reads the body but refuses the write with 403."
        }
    ),
    "list-rooms": frozenset(
        {"Lists caller-chosen room names and topics; returned content is untrusted."}
    ),
    "read-room": frozenset(
        {"Reads a room. Room content, writer names, and topics are untrusted data."}
    ),
    "post-room": frozenset(
        {"POST to a room may append public or capability-scoped content."}
    ),
    "unsigned-room-write": frozenset(
        {"This GET-shaped URL appends a message. Visiting it is a write operation."}
    ),
    "signed-room-write": frozenset(
        {"This URL contains replay-sensitive signed write material and appends a message."}
    ),
    "list-notes": frozenset(
        {"Lists note keys in a caller-chosen namespace; names and values are untrusted."}
    ),
    "read-note": frozenset(
        {"Reads a public or capability-addressed note. Its value is untrusted data."}
    ),
    "post-note": frozenset(
        {"POST may replace a note and may carry conditional-write semantics."}
    ),
    "unsigned-note-write": frozenset(
        {"This GET-shaped URL creates or replaces a note."}
    ),
    "signed-note-write": frozenset(
        {"This URL contains replay-sensitive signed material and attempts a protected note write."}
    ),
    "unknown-route": frozenset(
        {"The host is official but this route/method is not in the reviewed policy. Do not execute it."}
    ),
}
_ROUTE_REASONS.update(_BLOCKED_REASONS)

_READ_ROUTE_IDS = frozenset(
    {
        "static-document",
        "stats-read",
        "events-discovery",
        "list-rooms",
        "read-room",
        "list-notes",
        "read-note",
    }
)
_WRITE_ROUTE_IDS = frozenset(
    {
        "post-room",
        "post-events-reserved",
        "unsigned-room-write",
        "signed-room-write",
        "post-note",
        "unsigned-note-write",
        "signed-note-write",
    }
)
_POST_ROUTE_IDS = frozenset({"post-room", "post-events-reserved", "post-note"})
_SIGNED_ROUTE_IDS = frozenset({"signed-room-write", "signed-note-write"})
_BLOCKED_ROUTE_IDS = frozenset(_BLOCKED_REASONS)


def validate_public_event(event: Mapping[str, Any]) -> None:
    """Reject values outside the fixed, redacted inspection wire schema."""

    if type(event) is not dict or set(event) != set(PUBLIC_EVENT_FIELDS):
        raise ValueError("inspection does not match the public event schema")
    if event["schema"] != _SCHEMA or event["method"] not in _PUBLIC_METHODS:
        raise ValueError("inspection contains unsupported public values")
    if event["origin"] not in {_OFFICIAL_ORIGIN, None}:
        raise ValueError("inspection contains unsupported public values")
    if event["effect"] not in {item.value for item in Effect}:
        raise ValueError("inspection contains unsupported public values")
    if event["risk"] not in {item.value for item in Risk}:
        raise ValueError("inspection contains unsupported public values")

    route_id = event["route_id"]
    if route_id not in _ROUTE_REASONS:
        raise ValueError("inspection contains unsupported public values")
    targets = (
        frozenset({"<blocked>"})
        if route_id in _BLOCKED_ROUTE_IDS
        else _ROUTE_TARGETS.get(route_id, frozenset())
    )
    if event["sanitized_target"] not in targets:
        raise ValueError("inspection contains unsupported public values")
    expected_capability = "<private-" in event["sanitized_target"]

    warnings = event["warnings"]
    if (
        type(warnings) is not list
        or any(type(value) is not str or value not in _WARNING_VALUES for value in warnings)
        or warnings != sorted(set(warnings))
    ):
        raise ValueError("inspection contains unsupported public values")
    reason = event["reason"]
    base_reasons = _ROUTE_REASONS[route_id]
    expected_reasons = (
        {base + _QUERY_REVIEW_SUFFIX for base in base_reasons} if warnings else set(base_reasons)
    )
    if reason not in expected_reasons:
        raise ValueError("inspection contains unsupported public values")

    boolean_fields = (
        "contains_private_capability",
        "contains_user_content",
        "contains_replay_material",
        "network_executed",
    )
    if any(type(event[name]) is not bool for name in boolean_fields):
        raise ValueError("inspection contains unsupported public values")
    if event["network_executed"] is not False:
        raise ValueError("inspection contains unsupported public values")

    effect = event["effect"]
    if route_id in _BLOCKED_ROUTE_IDS:
        if (
            effect != Effect.BLOCKED.value
            or event["risk"] != Risk.CRITICAL.value
            or event["origin"] is not None
            or warnings
        ):
            raise ValueError("inspection contains unsupported public values")
        expected_method = "<unsupported>" if route_id == "unsupported-method" else None
        if expected_method and event["method"] != expected_method:
            raise ValueError("inspection contains unsupported public values")
        if expected_method is None and event["method"] not in _SUPPORTED_METHODS:
            raise ValueError("inspection contains unsupported public values")
    elif route_id == "unknown-route":
        if (
            effect != Effect.UNKNOWN.value
            or event["risk"] != Risk.HIGH.value
            or event["origin"] != _OFFICIAL_ORIGIN
            or event["method"] not in _SUPPORTED_METHODS
            or warnings
        ):
            raise ValueError("inspection contains unsupported public values")
    elif route_id in _WRITE_ROUTE_IDS:
        allowed_methods = {"POST"} if route_id in _POST_ROUTE_IDS else {"GET", "HEAD"}
        if (
            effect != Effect.WRITE.value
            or event["risk"] != Risk.CRITICAL.value
            or event["origin"] != _OFFICIAL_ORIGIN
            or event["method"] not in allowed_methods
        ):
            raise ValueError("inspection contains unsupported public values")
    elif route_id in _READ_ROUTE_IDS:
        if warnings:
            expected_risk = Risk.HIGH.value
        elif route_id == "static-document":
            expected_risk = Risk.LOW.value
        elif route_id == "stats-read":
            expected_risk = Risk.HIGH.value
        elif expected_capability:
            expected_risk = Risk.HIGH.value
        else:
            expected_risk = Risk.MEDIUM.value
        if (
            effect != Effect.READ.value
            or event["risk"] != expected_risk
            or event["origin"] != _OFFICIAL_ORIGIN
            or event["method"] not in {"GET", "HEAD"}
        ):
            raise ValueError("inspection contains unsupported public values")
    else:
        raise ValueError("inspection contains unsupported public values")

    if event["contains_private_capability"] is not expected_capability:
        raise ValueError("inspection contains unsupported public values")
    if event["contains_user_content"] is not (route_id in _WRITE_ROUTE_IDS):
        raise ValueError("inspection contains unsupported public values")
    expected_replay = route_id in (_SIGNED_ROUTE_IDS | _POST_ROUTE_IDS)
    if event["contains_replay_material"] is not expected_replay:
        raise ValueError("inspection contains unsupported public values")


@dataclass(frozen=True, slots=True)
class Inspection:
    schema: str
    method: str
    origin: str | None
    effect: Effect
    risk: Risk
    route_id: str
    sanitized_target: str
    reason: str
    warnings: tuple[str, ...] = field(default_factory=tuple)
    contains_private_capability: bool = False
    contains_user_content: bool = False
    contains_replay_material: bool = False
    network_executed: bool = False

    def to_public_dict(self) -> dict[str, Any]:
        """Return a serialisable, intentionally redacted representation.

        The raw URL and deterministic hashes of private input are never retained.
        Room capabilities, private note locations, user content, signatures, and
        nonces are represented only by fixed placeholders.
        """

        try:
            data = {
                "schema": self.schema,
                "method": self.method,
                "origin": self.origin,
                "effect": self.effect.value,
                "risk": self.risk.value,
                "route_id": self.route_id,
                "sanitized_target": self.sanitized_target,
                "reason": self.reason,
                "warnings": list(self.warnings),
                "contains_private_capability": self.contains_private_capability,
                "contains_user_content": self.contains_user_content,
                "contains_replay_material": self.contains_replay_material,
                "network_executed": self.network_executed,
            }
            validate_public_event(data)
        except (AttributeError, TypeError, ValueError):
            raise ValueError("inspection is not safe for public serialization") from None
        return data
