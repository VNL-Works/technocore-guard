from __future__ import annotations

import re
import unicodedata
import urllib.parse
from dataclasses import dataclass

from .models import Effect, Inspection, Risk

OFFICIAL_HOST = "technocore.chat"
OFFICIAL_ORIGIN = f"https://{OFFICIAL_HOST}"
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
ASCII_DIGITS_RE = re.compile(r"^[0-9]{1,19}$")
DID_RE = re.compile(r"^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$")
SIGNATURE_RE = re.compile(r"^[A-Za-z0-9_-]{85}[AQgw]$")

STATIC_READ_PATHS = {
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
}
READ_QUERY_KEYS = {"format", "since", "limit", "wait", "n"}
WRITE_QUERY_KEYS = {"format", "if", "if_absent"}
INVISIBLE_CATEGORIES = {"Cc", "Cf", "Cs", "Co", "Zl", "Zp"}
ENCODED_DELIMITER_BYTES = {0x2F, 0x3F, 0x23, 0x5C, 0x25}  # / ? # \ %


@dataclass(frozen=True, slots=True)
class _Route:
    effect: Effect
    risk: Risk
    route_id: str
    sanitized: str
    reason: str
    capability: bool = False
    content: bool = False
    replay: bool = False
    allowed_query_keys: frozenset[str] = frozenset()


def _result(
    method: str,
    *,
    effect: Effect,
    risk: Risk,
    route_id: str,
    sanitized: str,
    reason: str,
    warnings: tuple[str, ...] = (),
    capability: bool = False,
    content: bool = False,
    replay: bool = False,
    origin: str | None = OFFICIAL_ORIGIN,
) -> Inspection:
    return Inspection(
        schema="technocore-guard-inspection-v1",
        method=method,
        origin=origin,
        effect=effect,
        risk=risk,
        route_id=route_id,
        sanitized_target=sanitized,
        reason=reason,
        warnings=warnings,
        contains_private_capability=capability,
        contains_user_content=content,
        contains_replay_material=replay,
        network_executed=False,
    )


def _blocked(method: str, route_id: str, reason: str) -> Inspection:
    return _result(
        method,
        effect=Effect.BLOCKED,
        risk=Risk.CRITICAL,
        route_id=route_id,
        sanitized="<blocked>",
        reason=reason,
        origin=None,
    )


def _has_invisible(value: str) -> bool:
    return any(unicodedata.category(ch) in INVISIBLE_CATEGORIES for ch in value)


def _encoded_bytes(value: str) -> list[int] | None:
    """Return percent-encoded byte values, or None when an escape is malformed."""

    out: list[int] = []
    i = 0
    while i < len(value):
        if value[i] != "%":
            i += 1
            continue
        if i + 2 >= len(value) or not re.fullmatch(r"[0-9A-Fa-f]{2}", value[i + 1 : i + 3]):
            return None
        out.append(int(value[i + 1 : i + 3], 16))
        i += 3
    return out


def _decode_segment(raw: str) -> str:
    # Decode components separately so an encoded slash cannot silently become
    # another routing boundary inside this classifier.
    return urllib.parse.unquote(raw, encoding="utf-8", errors="strict")


def _room_classes(name: str) -> set[str]:
    classes: set[str] = set()
    rest = name
    while True:
        matched = False
        for prefix in ("mb-", "d-", "e-", "p-"):
            if rest.startswith(prefix):
                classes.add(prefix[:-1])
                rest = rest[len(prefix) :]
                matched = True
                break
        if not matched:
            return classes


def _valid_name(raw: str) -> tuple[bool, str]:
    try:
        decoded = _decode_segment(raw)
    except UnicodeDecodeError:
        return False, ""
    return bool(NAME_RE.fullmatch(decoded)), decoded


def _note_capability(namespace: str, key: str | None = None) -> bool:
    return "p" in _room_classes(namespace) or (
        key is not None and "p" in _room_classes(key)
    )


def _note_target(namespace_private: bool, key_private: bool, suffix: str = "") -> str:
    namespace = "<private-namespace>" if namespace_private else "<namespace>"
    key = "<private-key>" if key_private else "<key>"
    return f"/kv/{namespace}/{key}{suffix}"


def _query_warnings(query: str, allowed: frozenset[str]) -> tuple[str, ...] | None:
    if not query:
        return ()
    try:
        pairs = urllib.parse.parse_qsl(
            query,
            keep_blank_values=True,
            strict_parsing=False,
            encoding="utf-8",
            errors="strict",
            max_num_fields=50,
        )
    except (UnicodeDecodeError, ValueError):
        return None
    warnings: list[str] = []
    seen: set[str] = set()
    present: set[str] = set()
    for key, value in pairs:
        if _has_invisible(key) or _has_invisible(value):
            return None
        if key in seen:
            warnings.append("one or more duplicate query parameters are present")
        seen.add(key)
        present.add(key)
        if key not in allowed:
            warnings.append("one or more unknown query parameters are present")
    if {"if", "if_absent"}.issubset(present):
        warnings.append("conflicting conditional query parameters are present")
    return tuple(sorted(set(warnings)))


def _classify_route(path: str, method: str) -> _Route | None:
    if path in STATIC_READ_PATHS:
        if method in {"GET", "HEAD"}:
            return _Route(
                Effect.READ,
                Risk.LOW,
                "static-document",
                path,
                "Official-origin static or status document; this tool still does not fetch it.",
                allowed_query_keys=frozenset({"format"}),
            )
        return None

    if path == "/rooms":
        if method in {"GET", "HEAD"}:
            return _Route(
                Effect.READ,
                Risk.MEDIUM,
                "list-rooms",
                "/rooms",
                "Lists caller-chosen room names and topics; returned content is untrusted.",
                allowed_query_keys=frozenset(READ_QUERY_KEYS),
            )
        return None

    raw_segments = path.split("/")[1:]
    if not raw_segments or any(segment == "" for segment in raw_segments):
        return None

    # /r/<room>
    if len(raw_segments) == 2 and raw_segments[0] == "r":
        ok, room = _valid_name(raw_segments[1])
        if not ok:
            return None
        capability = "p" in _room_classes(room)
        if method in {"GET", "HEAD"}:
            return _Route(
                Effect.READ,
                Risk.HIGH if capability else Risk.MEDIUM,
                "read-room",
                "/r/<private-room>" if capability else "/r/<room>",
                "Reads a room. Room content, writer names, and topics are untrusted data.",
                capability=capability,
                allowed_query_keys=frozenset(READ_QUERY_KEYS),
            )
        if method == "POST":
            return _Route(
                Effect.WRITE,
                Risk.CRITICAL,
                "post-room",
                "/r/<private-room>" if capability else "/r/<room>",
                "POST to a room may append public or capability-scoped content.",
                capability=capability,
                content=True,
                replay=True,
                allowed_query_keys=frozenset({"format"}),
            )
        return None

    # GET /r/<room>/say/<nick>/<text>
    if len(raw_segments) == 5 and raw_segments[0] == "r" and raw_segments[2] == "say":
        ok_room, room = _valid_name(raw_segments[1])
        ok_nick, _nick = _valid_name(raw_segments[3])
        if not ok_room or not ok_nick or method not in {"GET", "HEAD"}:
            return None
        capability = "p" in _room_classes(room)
        return _Route(
            Effect.WRITE,
            Risk.CRITICAL,
            "unsigned-room-write",
            "/r/<private-room>/say/<nick>/<text>" if capability else "/r/<room>/say/<nick>/<text>",
            "This GET-shaped URL appends a message. Visiting it is a write operation.",
            capability=capability,
            content=True,
            allowed_query_keys=frozenset({"format"}),
        )

    # GET /r/<room>/say-signed/<did>/<sig>/<nonce>/<text>
    if len(raw_segments) == 7 and raw_segments[0] == "r" and raw_segments[2] == "say-signed":
        ok_room, room = _valid_name(raw_segments[1])
        try:
            did = _decode_segment(raw_segments[3])
            signature = _decode_segment(raw_segments[4])
            nonce = _decode_segment(raw_segments[5])
        except UnicodeDecodeError:
            return None
        if (
            not ok_room
            or not DID_RE.fullmatch(did)
            or not SIGNATURE_RE.fullmatch(signature)
            or not ASCII_DIGITS_RE.fullmatch(nonce)
            or method not in {"GET", "HEAD"}
        ):
            return None
        capability = "p" in _room_classes(room)
        return _Route(
            Effect.WRITE,
            Risk.CRITICAL,
            "signed-room-write",
            "/r/<private-room>/say-signed/<did>/<signature>/<nonce>/<text>"
            if capability
            else "/r/<room>/say-signed/<did>/<signature>/<nonce>/<text>",
            "This URL contains replay-sensitive signed write material and appends a message.",
            capability=capability,
            content=True,
            replay=True,
            allowed_query_keys=frozenset({"format"}),
        )

    # /kv/<namespace>
    if len(raw_segments) == 2 and raw_segments[0] == "kv":
        ok_ns, namespace = _valid_name(raw_segments[1])
        if ok_ns and method in {"GET", "HEAD"}:
            capability = _note_capability(namespace)
            return _Route(
                Effect.READ,
                Risk.HIGH if capability else Risk.MEDIUM,
                "list-notes",
                "/kv/<private-namespace>" if capability else "/kv/<namespace>",
                "Lists note keys in a caller-chosen namespace; names and values are untrusted.",
                capability=capability,
                allowed_query_keys=frozenset({"format"}),
            )
        return None

    # /kv/<namespace>/<key>
    if len(raw_segments) == 3 and raw_segments[0] == "kv":
        ok_ns, namespace = _valid_name(raw_segments[1])
        ok_key, key = _valid_name(raw_segments[2])
        if not ok_ns or not ok_key:
            return None
        namespace_private = "p" in _room_classes(namespace)
        key_private = "p" in _room_classes(key)
        capability = namespace_private or key_private
        if method in {"GET", "HEAD"}:
            return _Route(
                Effect.READ,
                Risk.HIGH if capability else Risk.MEDIUM,
                "read-note",
                _note_target(namespace_private, key_private),
                "Reads a public or capability-addressed note. Its value is untrusted data.",
                capability=capability,
                allowed_query_keys=frozenset({"format"}),
            )
        if method == "POST":
            return _Route(
                Effect.WRITE,
                Risk.CRITICAL,
                "post-note",
                _note_target(namespace_private, key_private),
                "POST may replace a note and may carry conditional-write semantics.",
                capability=capability,
                content=True,
                replay=True,
                allowed_query_keys=frozenset(WRITE_QUERY_KEYS),
            )
        return None

    # GET /kv/<namespace>/<key>/set/<value>
    if len(raw_segments) == 5 and raw_segments[0] == "kv" and raw_segments[3] == "set":
        ok_ns, namespace = _valid_name(raw_segments[1])
        ok_key, key = _valid_name(raw_segments[2])
        if not ok_ns or not ok_key or method not in {"GET", "HEAD"}:
            return None
        namespace_private = "p" in _room_classes(namespace)
        key_private = "p" in _room_classes(key)
        capability = namespace_private or key_private
        return _Route(
            Effect.WRITE,
            Risk.CRITICAL,
            "unsigned-note-write",
            _note_target(namespace_private, key_private, "/set/<value>"),
            "This GET-shaped URL creates or replaces a note.",
            capability=capability,
            content=True,
            allowed_query_keys=frozenset(WRITE_QUERY_KEYS),
        )

    # GET /kv/<namespace>/<key>/set-signed/<did>/<sig>/<nonce>/<value>
    if len(raw_segments) == 8 and raw_segments[0] == "kv" and raw_segments[3] == "set-signed":
        ok_ns, namespace = _valid_name(raw_segments[1])
        ok_key, key = _valid_name(raw_segments[2])
        try:
            did = _decode_segment(raw_segments[4])
            signature = _decode_segment(raw_segments[5])
            nonce = _decode_segment(raw_segments[6])
        except UnicodeDecodeError:
            return None
        if (
            not ok_ns
            or not ok_key
            or not DID_RE.fullmatch(did)
            or not SIGNATURE_RE.fullmatch(signature)
            or not ASCII_DIGITS_RE.fullmatch(nonce)
            or method not in {"GET", "HEAD"}
        ):
            return None
        namespace_private = "p" in _room_classes(namespace)
        key_private = "p" in _room_classes(key)
        capability = namespace_private or key_private
        return _Route(
            Effect.WRITE,
            Risk.CRITICAL,
            "signed-note-write",
            _note_target(
                namespace_private,
                key_private,
                "/set-signed/<did>/<signature>/<nonce>/<value>",
            ),
            "This URL contains replay-sensitive signed material and attempts a protected note write.",
            capability=capability,
            content=True,
            replay=True,
            allowed_query_keys=frozenset(WRITE_QUERY_KEYS),
        )

    return None


def inspect_url(raw_url: str, method: str = "GET") -> Inspection:
    """Classify one URL without opening it or resolving its host.

    The function fails closed. It intentionally refuses ambiguous encodings and
    does not retain the raw URL in its result.
    """

    if method not in {"GET", "HEAD", "POST"}:
        return _blocked(
            "<unsupported>",
            "unsupported-method",
            "Only GET, HEAD, and POST are modelled.",
        )
    if not raw_url or raw_url != raw_url.strip():
        return _blocked(method, "surrounding-whitespace", "URL has leading or trailing whitespace.")
    if any(character in " \t\r\n\f\v" for character in raw_url):
        return _blocked(
            method,
            "raw-whitespace",
            "Raw whitespace makes URL interpretation non-canonical.",
        )
    if _has_invisible(raw_url):
        return _blocked(
            method,
            "invisible-character",
            "URL contains control, format, surrogate, private-use, or line-separator characters.",
        )
    if "\\" in raw_url:
        return _blocked(method, "backslash", "Backslashes make authority and path interpretation ambiguous.")
    if len(raw_url.encode("utf-8", "surrogatepass")) > 16_384:
        return _blocked(method, "url-too-long", "URL exceeds the conservative 16 KiB inspection ceiling.")
    if not raw_url.startswith("https://"):
        return _blocked(method, "scheme", "Only canonical lowercase HTTPS is accepted.")
    if "#" in raw_url:
        return _blocked(method, "fragment", "Fragments are rejected even when empty.")

    try:
        parsed = urllib.parse.urlsplit(raw_url)
    except ValueError:
        return _blocked(method, "parse-error", "URL parser rejected the authority or port.")

    if parsed.scheme != "https":
        return _blocked(method, "scheme", "Only canonical lowercase HTTPS is accepted.")
    if not parsed.netloc:
        return _blocked(method, "missing-authority", "Absolute official-origin URL required.")
    if parsed.username is not None or parsed.password is not None:
        return _blocked(method, "userinfo", "Userinfo can disguise the actual destination host.")
    try:
        port = parsed.port
    except ValueError:
        return _blocked(method, "port", "Invalid port.")
    if port is not None:
        return _blocked(method, "port", "Explicit ports are non-canonical and rejected.")
    hostname = parsed.hostname
    if hostname is None:
        return _blocked(method, "missing-host", "Host is missing.")
    if hostname.endswith(".") or "%" in hostname:
        return _blocked(method, "host-spelling", "Trailing-dot and percent-encoded host spellings are rejected.")
    try:
        host_ascii = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return _blocked(method, "host-idna", "Host cannot be converted to a canonical IDNA spelling.")
    if host_ascii != OFFICIAL_HOST:
        return _blocked(method, "host", "Destination is not the exact official Technocore host.")
    if parsed.netloc != OFFICIAL_HOST:
        return _blocked(method, "authority-spelling", "Authority must be exactly technocore.chat with no aliases.")

    encoded = _encoded_bytes(parsed.path + ("?" + parsed.query if parsed.query else ""))
    if encoded is None:
        return _blocked(method, "bad-percent-escape", "Malformed percent escape.")
    if any(byte < 0x20 or byte == 0x7F for byte in encoded):
        return _blocked(method, "encoded-control", "Percent-encoded control characters are rejected.")
    if any(byte in ENCODED_DELIMITER_BYTES for byte in encoded):
        return _blocked(
            method,
            "encoded-delimiter",
            "Encoded routing delimiters or percent signs are ambiguous and rejected.",
        )

    try:
        decoded_once = urllib.parse.unquote(parsed.path, encoding="utf-8", errors="strict")
        decoded_twice = urllib.parse.unquote(decoded_once, encoding="utf-8", errors="strict")
    except UnicodeDecodeError:
        return _blocked(method, "path-encoding", "Path is not valid UTF-8 after percent-decoding.")
    if _has_invisible(decoded_once):
        return _blocked(
            method,
            "decoded-invisible",
            "Decoded path contains control, format, surrogate, private-use, or separator characters.",
        )
    if decoded_twice != decoded_once:
        return _blocked(method, "double-encoding", "A second decoding pass changes the path.")
    if any(part in {".", ".."} for part in decoded_once.split("/")):
        return _blocked(method, "dot-segment", "Dot segments are not valid Technocore names.")

    route = _classify_route(parsed.path, method)
    if route is None:
        return _result(
            method,
            effect=Effect.UNKNOWN,
            risk=Risk.HIGH,
            route_id="unknown-route",
            sanitized="<unknown-official-origin-route>",
            reason="The host is official but this route/method is not in the reviewed policy. Do not execute it.",
        )

    warnings = _query_warnings(parsed.query, route.allowed_query_keys)
    if warnings is None:
        return _blocked(method, "query-encoding", "Query cannot be parsed safely or contains invisible characters.")
    if warnings and route.effect == Effect.READ:
        return _result(
            method,
            effect=Effect.UNKNOWN,
            risk=Risk.HIGH,
            route_id="unknown-route",
            sanitized="<unknown-official-origin-route>",
            reason="The host is official but this route/method is not in the reviewed policy. Do not execute it.",
        )
    risk = route.risk
    reason = route.reason
    if warnings:
        risk = Risk.HIGH if route.effect == Effect.READ else Risk.CRITICAL
        reason += " Unknown query parameters require human review."

    return _result(
        method,
        effect=route.effect,
        risk=risk,
        route_id=route.route_id,
        sanitized=route.sanitized,
        reason=reason,
        warnings=warnings,
        capability=route.capability,
        content=route.content,
        replay=route.replay,
    )
