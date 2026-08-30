from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from .models import Inspection, validate_public_event

SCHEMA = "technocore-guard-ledger-v1"
GENESIS_HASH = "0" * 64


class LedgerError(RuntimeError):
    pass


FORBIDDEN_PATH_PARTS = {".secrets", ".agent", ".ssh", ".aws"}
FORBIDDEN_FILE_NAMES = {
    ".npmrc",
    ".netrc",
    "auth.json",
    "credentials",
    "credentials.json",
    "ed25519_seed.hex",
}
FORBIDDEN_NAME_FRAGMENTS = {
    "api-key",
    "api_key",
    "apikey",
    "client_secret",
    "mnemonic",
    "private-key",
    "private_key",
    "seed",
    "seed_phrase",
    "token",
    "wallet",
}
FORBIDDEN_KEY_SUFFIXES = {".key", ".p12", ".pem", ".pfx", ".seed"}
RECORD_FIELDS = {
    "schema",
    "seq",
    "created_at",
    "previous_record_sha256",
    "event_sha256",
    "event",
    "record_sha256",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
WINDOWS_SHARING_RETRY_DELAYS = (0.01, 0.02, 0.04, 0.08, 0.16)


class _DuplicateKeyError(ValueError):
    pass


class _NonFiniteNumberError(ValueError):
    pass


def _is_link_like(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        attributes = getattr(os.lstat(path), "st_file_attributes", 0)
        if attributes & 0x0400:  # Windows FILE_ATTRIBUTE_REPARSE_POINT.
            return True
        is_junction = getattr(path, "is_junction", None)
        return bool(is_junction and is_junction())
    except FileNotFoundError:
        return False
    except OSError:
        return True


def _has_forbidden_name(parts: tuple[str, ...]) -> bool:
    lowered = tuple(part.lower() for part in parts)
    if set(lowered) & FORBIDDEN_PATH_PARTS:
        return True
    pairs = set(zip(lowered, lowered[1:]))
    if (
        (".codex", "auth.json") in pairs
        or (".claude", ".credentials.json") in pairs
        or (".config", "gh") in pairs
    ):
        return True
    for name in lowered:
        if name == ".env" or name.startswith(".env."):
            return True
        if name.startswith(("id_dsa", "id_ecdsa", "id_ed25519", "id_rsa")):
            return True
        if name in FORBIDDEN_FILE_NAMES or any(
            fragment in name for fragment in FORBIDDEN_NAME_FRAGMENTS
        ):
            return True
        if name.endswith(tuple(FORBIDDEN_KEY_SUFFIXES)):
            return True
    return False


def _assert_safe_path(path: Path) -> None:
    absolute = path if path.is_absolute() else Path.cwd() / path
    if _has_forbidden_name(absolute.parts):
        raise LedgerError("refusing an identity- or credential-material ledger path")
    for candidate in (absolute, *absolute.parents):
        if _is_link_like(candidate):
            raise LedgerError("refusing a ledger path with a link-like component")


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateKeyError
        value[key] = item
    return value


def _reject_nonfinite(_value: str) -> None:
    raise _NonFiniteNumberError


def _parse_line(line: str, line_no: int) -> dict[str, Any]:
    try:
        value = json.loads(
            line,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_nonfinite,
        )
    except (json.JSONDecodeError, _DuplicateKeyError, _NonFiniteNumberError, RecursionError, ValueError):
        raise LedgerError(f"invalid JSON at line {line_no}") from None
    if type(value) is not dict:
        raise LedgerError(f"record at line {line_no} is not an object")
    return value


def _load(path: Path, *, require_exists: bool = False) -> list[dict[str, Any]]:
    _assert_safe_path(path)
    records: list[dict[str, Any]] = []
    try:
        if not path.exists():
            if require_exists:
                raise LedgerError("ledger does not exist")
            return records
        if _is_link_like(path):
            raise LedgerError("refusing a link-like ledger")
        if not path.is_file():
            raise LedgerError("ledger is not a regular file")
        with path.open("r", encoding="utf-8", newline="") as handle:
            for line_no, line in enumerate(handle, 1):
                if not line.strip():
                    raise LedgerError(f"blank line at {line_no}")
                records.append(_parse_line(line, line_no))
    except UnicodeError:
        raise LedgerError("ledger is not valid UTF-8") from None
    except OSError:
        raise LedgerError("local ledger read failed") from None
    return records


def _validate_timestamp(value: Any, *, record_number: int | None = None) -> None:
    label = f"record {record_number}: " if record_number is not None else ""
    if type(value) is not str or len(value) > 64 or not value.isascii():
        raise LedgerError(f"{label}created_at is not a canonical timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise LedgerError(f"{label}created_at is not a canonical timestamp") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None or parsed.isoformat() != value:
        raise LedgerError(f"{label}created_at is not a canonical timestamp")


def _checked_hash(value: Any, *, record_number: int) -> str:
    try:
        return _hash(value)
    except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
        raise LedgerError(f"record {record_number}: value is not canonical JSON") from None


def verify_records(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    previous = GENESIS_HASH
    count = 0
    for count, record in enumerate(records, 1):
        if type(record) is not dict or set(record) != RECORD_FIELDS:
            raise LedgerError(f"record {count}: wrong record schema")
        if record["schema"] != SCHEMA:
            raise LedgerError(f"record {count}: wrong schema")
        if type(record["seq"]) is not int or record["seq"] != count:
            raise LedgerError(f"record {count}: non-contiguous seq")
        _validate_timestamp(record["created_at"], record_number=count)
        for field_name in ("previous_record_sha256", "event_sha256", "record_sha256"):
            if type(record[field_name]) is not str or not SHA256_RE.fullmatch(record[field_name]):
                raise LedgerError(f"record {count}: malformed hash field")
        if record["previous_record_sha256"] != previous:
            raise LedgerError(f"record {count}: previous hash mismatch")
        event = record["event"]
        try:
            validate_public_event(event)
        except ValueError:
            raise LedgerError(f"record {count}: event violates the redacted schema") from None
        if record["event_sha256"] != _checked_hash(event, record_number=count):
            raise LedgerError(f"record {count}: event hash mismatch")
        unsigned = dict(record)
        recorded_hash = unsigned.pop("record_sha256")
        expected = _checked_hash(unsigned, record_number=count)
        if recorded_hash != expected:
            raise LedgerError(f"record {count}: record hash mismatch")
        previous = expected
    return {"valid": True, "records": count, "head_sha256": previous}


def verify_ledger(path: Path) -> dict[str, Any]:
    return verify_records(_load(path, require_exists=True))


def _is_windows_sharing_violation(error: OSError) -> bool:
    return getattr(error, "winerror", None) in {32, 33}


def _replace_with_retry(source: str, destination: Path) -> None:
    for delay in WINDOWS_SHARING_RETRY_DELAYS:
        try:
            os.replace(source, destination)
            return
        except OSError as exc:
            if not _is_windows_sharing_violation(exc):
                raise
        time.sleep(delay)
    os.replace(source, destination)


def _unlink_with_retry(path: str) -> None:
    for delay in WINDOWS_SHARING_RETRY_DELAYS:
        try:
            os.unlink(path)
            return
        except FileNotFoundError:
            return
        except OSError as exc:
            if not _is_windows_sharing_violation(exc):
                raise
        time.sleep(delay)
    try:
        os.unlink(path)
    except FileNotFoundError:
        return


def _atomic_write_lines(path: Path, records: list[dict[str, Any]]) -> None:
    _assert_safe_path(path)
    temp_name: str | None = None
    try:
        if path.exists() and _is_link_like(path):
            raise LedgerError("refusing to replace a link-like ledger")
        path.parent.mkdir(parents=True, exist_ok=True)
        _assert_safe_path(path)
        fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            for record in records:
                handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        _replace_with_retry(temp_name, path)
    except BaseException as exc:
        try:
            if temp_name is not None:
                _unlink_with_retry(temp_name)
        except OSError:
            pass
        if isinstance(exc, LedgerError):
            raise
        if isinstance(exc, (OSError, TypeError, ValueError, UnicodeError)):
            raise LedgerError("local ledger write failed") from None
        raise


def append_inspection(
    path: Path,
    inspection: Inspection,
    *,
    created_at: str | None = None,
) -> dict[str, Any]:
    _assert_safe_path(path)
    timestamp = datetime.now(UTC).isoformat() if created_at is None else created_at
    _validate_timestamp(timestamp)
    try:
        event = inspection.to_public_dict()
    except ValueError:
        raise LedgerError("inspection is not safe to record") from None
    records = _load(path)
    state = verify_records(records)
    record: dict[str, Any] = {
        "schema": SCHEMA,
        "seq": len(records) + 1,
        "created_at": timestamp,
        "previous_record_sha256": state["head_sha256"],
        "event_sha256": _hash(event),
        "event": event,
    }
    record["record_sha256"] = _hash(record)
    records.append(record)
    _atomic_write_lines(path, records)
    return record
