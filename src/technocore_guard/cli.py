from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .classifier import inspect_url
from .ledger import LedgerError, append_inspection, verify_ledger


class _RedactingArgumentParser(argparse.ArgumentParser):
    """Keep untrusted argument values out of parser error messages."""

    def error(self, _message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: invalid command line\n")


def _print_json(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = _RedactingArgumentParser(
        prog="tc-guard",
        description="Offline Technocore URL effect classifier. It never fetches the URL.",
        epilog="Exit 0 means a reviewed read/write classification; blocked, unknown, and errors use 2.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    inspect = sub.add_parser("inspect", help="Classify a URL without opening it.")
    inspect.add_argument(
        "url",
        help="Absolute URL, or - to read exactly one line from stdin (recommended for private URLs).",
    )
    inspect.add_argument(
        "--method",
        default="GET",
        metavar="{GET,HEAD,POST}",
        help="Explicit canonical method (default: GET). Other spellings are blocked.",
    )
    inspect.add_argument(
        "--record",
        type=Path,
        help="Append only the redacted result to a local ledger path.",
    )

    verify = sub.add_parser("verify-ledger", help="Verify a hash-chained JSONL ledger.")
    verify.add_argument("path", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "inspect":
            raw_url = args.url
            if raw_url == "-":
                first = sys.stdin.readline(16_386)
                remainder = sys.stdin.read(1)
                if not first or remainder:
                    print("ERROR: stdin mode requires exactly one URL line", file=sys.stderr)
                    return 2
                if first.endswith("\r\n"):
                    raw_url = first[:-2]
                elif first.endswith("\n"):
                    raw_url = first[:-1]
                elif first.endswith("\r"):
                    print("ERROR: stdin mode requires exactly one URL line", file=sys.stderr)
                    return 2
                else:
                    raw_url = first
            result = inspect_url(raw_url, args.method)
            payload = result.to_public_dict()
            if args.record:
                record = append_inspection(args.record, result)
                payload["ledger_record_sha256"] = record["record_sha256"]
                payload["ledger_recorded"] = True
            _print_json(payload)
            return 0 if result.effect.value in {"read", "write"} else 2
        if args.command == "verify-ledger":
            _print_json(verify_ledger(args.path))
            return 0
    except LedgerError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError):
        print("ERROR: local inspection operation failed", file=sys.stderr)
        return 2
    return 2
