"""Offline drift report between an upstream route registry and this guard.

The input is a locally saved copy of upstream technocore-chat ``src/app.py``.
It is parsed with ``ast`` only; it is never imported or executed. Every
extracted route and method is classified by this repository's real
``technocore_guard.classifier.inspect_url`` using fixed sample values, and a
deterministic JSON report is written. The report contains path templates only,
never sample URLs or sample values. No network access and no subprocess.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_GUARD_SRC = ROOT / "src"

SCHEMA = "technocore-guard-route-drift-v1"
FIXTURE_SOURCE = "technocore-chat/src/app.py route registry"
SAMPLE_ORIGIN = "https://technocore.chat"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)(?::([A-Za-z_][A-Za-z0-9_]*))?\}")
ALLOWED_CONVERTERS = {None, "str", "path"}
MODELLED_METHODS = {"GET", "HEAD", "POST"}

# Single-segment sample values accepted by the validators in classifier.py:
# NAME_RE for names, DID_RE, SIGNATURE_RE and ASCII_DIGITS_RE for signed
# material. None of them starts with a private "p-" class, and "lobby" is not
# a reserved room name. They never appear in the report.
SAMPLE_VALUES = {
    "room": "lobby",
    "nick": "bot",
    "text": "hello",
    "did": "did:key:z6Mk" + "1" * 44,
    "sig": "A" * 86,
    "nonce": "1",
    "ns": "topic",
    "key": "lobby",
    "value": "hello",
}

# Attribute names on the module-level ``app`` that could register routes
# outside the ``routes=[...]`` list. Their presence fails closed.
APP_ROUTE_ATTRIBUTES = {
    "add_route",
    "add_websocket_route",
    "host",
    "mount",
    "route",
    "router",
    "routes",
    "websocket_route",
}
DICT_MUTATORS = {"clear", "pop", "popitem", "setdefault", "update", "__setitem__", "__delitem__"}


class DriftError(Exception):
    """Extraction or sample error. The message never contains a URL."""

    def __init__(self, lineno: int | None, shape: str, detail: str = "") -> None:
        self.lineno = lineno
        self.shape = shape
        self.detail = detail
        super().__init__(self.render())

    def render(self) -> str:
        where = f"line {self.lineno}" if self.lineno is not None else "input"
        text = f"{where}: {self.shape}"
        return f"{text}: {self.detail}" if self.detail else text


class _UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # type: ignore[override]
        raise _UsageError(message)


@dataclass(frozen=True)
class RouteEntry:
    path: str
    methods: frozenset[str]
    get_write: bool
    lineno: int


# --------------------------------------------------------------------------
# Static extraction
# --------------------------------------------------------------------------


def _literal_str(node: ast.AST, what: str) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    raise DriftError(getattr(node, "lineno", None), "non-literal path", what)


def _is_name(node: ast.AST, name: str | None = None) -> bool:
    return isinstance(node, ast.Name) and (name is None or node.id == name)


def _module_assignments(tree: ast.Module, name: str) -> list[ast.Assign]:
    found: list[ast.Assign] = []
    for statement in tree.body:
        if isinstance(statement, ast.Assign):
            if any(_is_name(target, name) for target in statement.targets):
                if len(statement.targets) != 1:
                    raise DriftError(statement.lineno, "unsupported assignment", f"chained assignment to {name}")
                found.append(statement)
        elif isinstance(statement, (ast.AnnAssign, ast.AugAssign)) and _is_name(statement.target, name):
            raise DriftError(statement.lineno, "unsupported assignment", f"annotated or augmented {name}")
    return found


def _store_lines(tree: ast.Module, name: str, allowed: ast.Assign | None) -> list[int]:
    allowed_target = allowed.targets[0] if allowed is not None else None
    lines: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, (ast.Store, ast.Del)):
            if node is not allowed_target:
                lines.append(node.lineno)
    return sorted(lines)


def _find_app_routes(tree: ast.Module) -> ast.List:
    assignments = _module_assignments(tree, "app")
    if not assignments:
        raise DriftError(None, "missing app", "no module-level `app = Starlette(routes=[...])`")
    if len(assignments) > 1:
        raise DriftError(assignments[1].lineno, "ambiguous app", "more than one module-level `app` assignment")
    assignment = assignments[0]
    other = _store_lines(tree, "app", assignment)
    if other:
        raise DriftError(other[0], "ambiguous app", "`app` is rebound outside the module-level assignment")
    call = assignment.value
    if not (isinstance(call, ast.Call) and _is_name(call.func, "Starlette")):
        raise DriftError(assignment.lineno, "missing app", "`app` is not assigned a `Starlette(...)` call")
    routes = [keyword for keyword in call.keywords if keyword.arg == "routes"]
    if len(routes) != 1:
        raise DriftError(assignment.lineno, "missing app", "`Starlette(...)` has no single `routes=` keyword")
    if any(keyword.arg is None for keyword in call.keywords):
        raise DriftError(assignment.lineno, "unsupported app shape", "`**` keyword expansion in Starlette call")
    value = routes[0].value
    if not isinstance(value, ast.List):
        raise DriftError(value.lineno, "unsupported app shape", "`routes=` is not a list literal")
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and _is_name(node.value, "app")
            and node.attr in APP_ROUTE_ATTRIBUTES
        ):
            raise DriftError(node.lineno, "unsupported route registration", f"`app.{node.attr}` outside `routes=`")
    return value


def _docs_keys(tree: ast.Module, lineno: int) -> list[str]:
    assignments = _module_assignments(tree, "_DOCS")
    if not assignments:
        raise DriftError(lineno, "missing _DOCS", "comprehension iterates `_DOCS` but no module-level dict exists")
    if len(assignments) > 1:
        raise DriftError(assignments[1].lineno, "ambiguous _DOCS", "more than one module-level `_DOCS` assignment")
    assignment = assignments[0]
    other = _store_lines(tree, "_DOCS", assignment)
    if other:
        raise DriftError(other[0], "ambiguous _DOCS", "`_DOCS` is rebound outside the module-level assignment")
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Subscript)
            and _is_name(node.value, "_DOCS")
            and isinstance(node.ctx, (ast.Store, ast.Del))
        ):
            raise DriftError(node.lineno, "ambiguous _DOCS", "`_DOCS` item is assigned or deleted")
        if isinstance(node, ast.Attribute) and _is_name(node.value, "_DOCS") and node.attr in DICT_MUTATORS:
            raise DriftError(node.lineno, "ambiguous _DOCS", f"`_DOCS.{node.attr}` may change its keys")
    value = assignment.value
    if not isinstance(value, ast.Dict):
        raise DriftError(assignment.lineno, "unsupported _DOCS shape", "`_DOCS` is not a dict literal")
    keys: list[str] = []
    for key in value.keys:
        if key is None:
            raise DriftError(assignment.lineno, "non-literal _DOCS key", "`**` expansion in `_DOCS`")
        if not (isinstance(key, ast.Constant) and isinstance(key.value, str)):
            raise DriftError(key.lineno, "non-literal _DOCS key", "key is not a string literal")
        keys.append(key.value)
    return keys


def _methods_keyword(call: ast.Call) -> frozenset[str]:
    if not call.keywords:
        return frozenset({"GET", "HEAD"})
    if len(call.keywords) != 1 or call.keywords[0].arg != "methods":
        raise DriftError(call.lineno, "unknown route shape", "Route keyword other than a single `methods=`")
    value = call.keywords[0].value
    if not isinstance(value, ast.List) or not value.elts:
        raise DriftError(call.lineno, "unknown route shape", "`methods=` is not a non-empty list literal")
    methods: set[str] = set()
    for element in value.elts:
        if not (isinstance(element, ast.Constant) and isinstance(element.value, str)):
            raise DriftError(call.lineno, "unknown route shape", "`methods=` element is not a string literal")
        methods.add(element.value.upper())
    if "GET" in methods:
        methods.add("HEAD")
    return frozenset(methods)


def _extract_call(call: ast.Call) -> RouteEntry:
    if _is_name(call.func, "Route"):
        if len(call.args) != 2 or not _is_name(call.args[1]):
            raise DriftError(call.lineno, "unknown route shape", "Route needs exactly a path literal and an endpoint name")
        path = _literal_str(call.args[0], "Route path is not a string literal")
        return RouteEntry(path, _methods_keyword(call), False, call.lineno)
    if _is_name(call.func, "_get_write"):
        if len(call.args) != 2 or call.keywords or not _is_name(call.args[1]):
            raise DriftError(call.lineno, "unknown route shape", "_get_write needs exactly a path literal and an endpoint name")
        path = _literal_str(call.args[0], "_get_write path is not a string literal")
        return RouteEntry(path, frozenset({"GET"}), True, call.lineno)
    raise DriftError(call.lineno, "unknown route shape", "call is neither Route nor _get_write")


def _extract_starred(tree: ast.Module, starred: ast.Starred) -> list[RouteEntry]:
    comp = starred.value
    lineno = starred.lineno
    if not isinstance(comp, ast.ListComp) or len(comp.generators) != 1:
        raise DriftError(lineno, "unknown route shape", "starred element is not a single-generator list comprehension")
    generator = comp.generators[0]
    if generator.ifs or generator.is_async or not _is_name(generator.target):
        raise DriftError(lineno, "unknown route shape", "comprehension has a filter, async, or non-name target")
    target = generator.target.id  # type: ignore[union-attr]
    element = comp.elt
    if not (
        isinstance(element, ast.Call)
        and _is_name(element.func, "Route")
        and len(element.args) == 2
        and not element.keywords
        and _is_name(element.args[0], target)
        and _is_name(element.args[1])
    ):
        raise DriftError(lineno, "unknown route shape", "comprehension element is not `Route(<target>, <name>)`")
    iterable = generator.iter
    if isinstance(iterable, ast.Tuple):
        paths = [_literal_str(item, "comprehension tuple item is not a string literal") for item in iterable.elts]
    elif _is_name(iterable, "_DOCS"):
        paths = _docs_keys(tree, lineno)
    else:
        raise DriftError(lineno, "unknown route shape", "comprehension iterates neither a literal tuple nor `_DOCS`")
    return [RouteEntry(path, frozenset({"GET", "HEAD"}), False, lineno) for path in paths]


def extract_routes(source: str) -> list[RouteEntry]:
    try:
        tree = ast.parse(source, filename="<app.py>")
    except SyntaxError as exc:
        raise DriftError(exc.lineno, "syntax error", "input is not parseable Python") from None
    routes = _find_app_routes(tree)
    entries: list[RouteEntry] = []
    for element in routes.elts:
        if isinstance(element, ast.Call):
            entries.append(_extract_call(element))
        elif isinstance(element, ast.Starred):
            entries.extend(_extract_starred(tree, element))
        else:
            raise DriftError(
                getattr(element, "lineno", None),
                "unknown route shape",
                f"unsupported element {type(element).__name__}",
            )
    for entry in entries:
        _sample_path(entry.path, entry.lineno)  # validate templates early
    return entries


# --------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------


def _sample_path(template: str, lineno: int) -> str:
    if not template.startswith("/"):
        raise DriftError(lineno, "unsupported path template", f"{template!r} does not start with '/'")

    def fill(match: re.Match[str]) -> str:
        name, converter = match.group(1), match.group(2)
        if converter not in ALLOWED_CONVERTERS:
            raise DriftError(lineno, "unsupported path template", f"converter {converter!r} in {template!r}")
        if name not in SAMPLE_VALUES:
            raise DriftError(lineno, "unknown placeholder", f"{{{name}}} in {template!r} has no sample value")
        return SAMPLE_VALUES[name]

    filled = PLACEHOLDER_RE.sub(fill, template)
    if "{" in filled or "}" in filled:
        raise DriftError(lineno, "unsupported path template", f"malformed placeholder in {template!r}")
    return filled


def _load_classifier(guard_src: Path):
    src = guard_src.resolve()
    if not (src / "technocore_guard" / "classifier.py").is_file():
        raise DriftError(None, "guard src", "no technocore_guard/classifier.py under --guard-src")
    if str(src) not in sys.path:
        sys.path.insert(0, str(src))
    import technocore_guard.classifier as classifier

    loaded = Path(classifier.__file__).resolve()
    try:
        loaded.relative_to(src)
    except ValueError:
        raise DriftError(
            None,
            "guard src",
            "technocore_guard is already imported from a different source tree",
        ) from None
    return classifier


def build_report(entries: Sequence[RouteEntry], commit: str, classifier) -> dict[str, object]:
    merged: dict[str, set[str]] = {}
    lines: dict[str, int] = {}
    write_shaped: set[tuple[str, str]] = set()
    for entry in entries:
        merged.setdefault(entry.path, set()).update(entry.methods)
        lines.setdefault(entry.path, entry.lineno)
        if entry.get_write:
            write_shaped.update((entry.path, method) for method in entry.methods)
        if "POST" in entry.methods:
            write_shaped.add((entry.path, "POST"))

    classified: list[dict[str, str]] = []
    for path in sorted(merged):
        for method in sorted(merged[path]):
            if method not in MODELLED_METHODS:
                raise DriftError(lines[path], "unsupported method", f"{method} on {path!r} is not modelled")
            url = SAMPLE_ORIGIN + _sample_path(path, lines[path])
            inspection = classifier.inspect_url(url, method)
            effect = str(getattr(inspection.effect, "value", inspection.effect))
            if effect == "blocked":
                raise DriftError(
                    lines[path],
                    "sample_rejected",
                    f"{method} {path!r} sample was refused ({inspection.route_id})",
                )
            classified.append(
                {"path": path, "method": method, "effect": effect, "route_id": inspection.route_id}
            )

    uncovered = [row for row in classified if row["effect"] == "unknown"]
    write_misclassified = [
        row
        for row in classified
        if (row["path"], row["method"]) in write_shaped and row["effect"] != "write"
    ]
    stale = sorted(set(classifier.STATIC_READ_PATHS) - set(merged))
    return {
        "schema": SCHEMA,
        "upstream_commit": commit,
        "upstream_routes": [
            {"path": path, "methods": sorted(merged[path])} for path in sorted(merged)
        ],
        "classified": classified,
        "uncovered": uncovered,
        "write_misclassified": write_misclassified,
        "stale_static_paths": stale,
        "drift": bool(uncovered or write_misclassified or stale),
    }


def render_report(report: dict[str, object]) -> str:
    return json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True) + "\n"


def render_fixture(report: dict[str, object]) -> str:
    rows = [
        "    " + json.dumps([route["path"], route["methods"]], ensure_ascii=True)
        for route in report["upstream_routes"]  # type: ignore[union-attr]
    ]
    return (
        "{\n"
        f'  "source": {json.dumps(FIXTURE_SOURCE)},\n'
        f'  "commit": {json.dumps(report["upstream_commit"])},\n'
        '  "routes": [\n'
        + ",\n".join(rows)
        + ("\n" if rows else "")
        + "  ]\n"
        "}\n"
    )


def _write_text(path: Path, text: str) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def _write_stdout(text: str) -> None:
    buffer = getattr(sys.stdout, "buffer", None)
    if buffer is None:
        sys.stdout.write(text)
        return
    sys.stdout.flush()
    buffer.write(text.encode("utf-8"))
    buffer.flush()


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="route_drift.py",
        description="Offline drift report: upstream app.py route registry vs this guard's classifier.",
    )
    parser.add_argument("--app-py", required=True, type=Path, help="Local copy of upstream src/app.py.")
    parser.add_argument("--upstream-commit", required=True, help="40-hex upstream commit, recorded as given.")
    parser.add_argument("--out", type=Path, help="Write the JSON report here instead of stdout.")
    parser.add_argument("--fixture-out", type=Path, help="Also write a route fixture in the PR #1 layout.")
    parser.add_argument(
        "--guard-src",
        type=Path,
        default=DEFAULT_GUARD_SRC,
        help="Directory containing technocore_guard (default: this repository's src).",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(list(argv) if argv is not None else None)
    except _UsageError as exc:
        print(f"route_drift: usage error: {exc}", file=sys.stderr)
        return 2
    if not COMMIT_RE.fullmatch(args.upstream_commit):
        print("route_drift: error: --upstream-commit must be 40 lowercase hex characters", file=sys.stderr)
        return 2
    try:
        try:
            source = args.app_py.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise DriftError(None, "read error", f"cannot read --app-py ({type(exc).__name__})") from None
        entries = extract_routes(source)
        classifier = _load_classifier(args.guard_src)
        report = build_report(entries, args.upstream_commit, classifier)
    except DriftError as exc:
        print(f"route_drift: error: {exc.render()}", file=sys.stderr)
        return 2

    text = render_report(report)
    for option, destination, content in (
        ("--out", args.out, text),
        ("--fixture-out", args.fixture_out, render_fixture(report)),
    ):
        if destination is None:
            continue
        try:
            _write_text(destination, content)
        except OSError as exc:
            print(f"route_drift: error: cannot write {option} ({type(exc).__name__})", file=sys.stderr)
            return 2
    if args.out is None:
        _write_stdout(text)
    return 1 if report["drift"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
