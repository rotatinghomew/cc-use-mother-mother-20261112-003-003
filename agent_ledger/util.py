from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator, Mapping, Sequence, TypeVar

from .errors import ValidationError

T = TypeVar("T")

UTC = timezone.utc
IDENTIFIER = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{0,127}$")
REGION = re.compile(r"^[A-Z]{2}(?:-[A-Z0-9]{1,3})?$")
CAPABILITY = re.compile(r"^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$")
VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){0,3}(?:[-+][a-zA-Z0-9.-]+)?$")


def utc_now() -> datetime:
    return datetime.now(UTC)


def parse_time(value: str | datetime, field: str = "time") -> datetime:
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            result = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ValidationError("invalid timestamp", details={"field": field, "value": value}) from exc
    else:
        raise ValidationError("timestamp must be a string", details={"field": field})
    if result.tzinfo is None:
        raise ValidationError("timestamp requires an offset", details={"field": field})
    return result.astimezone(UTC)


def format_time(value: datetime | None) -> str | None:
    if value is None:
        return None
    normalized = value.astimezone(UTC)
    return normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(value: bytes | str) -> str:
    data = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


def stable_id(prefix: str, value: Any) -> str:
    return f"{prefix}_{sha256_hex(canonical_json(value))[:24]}"


def encode_token(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def decode_token(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except Exception as exc:
        raise ValidationError("invalid base64 token") from exc


def ensure_identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValidationError("invalid identifier", details={"field": field, "value": value})
    return value


def ensure_region(value: Any, field: str = "region") -> str:
    if not isinstance(value, str) or not REGION.fullmatch(value):
        raise ValidationError("invalid region", details={"field": field, "value": value})
    return value


def ensure_capability(value: Any, field: str = "capability") -> str:
    if not isinstance(value, str) or not CAPABILITY.fullmatch(value):
        raise ValidationError("invalid capability", details={"field": field, "value": value})
    return value


def ensure_version(value: Any, field: str = "version") -> str:
    if not isinstance(value, str) or not VERSION.fullmatch(value):
        raise ValidationError("invalid version", details={"field": field, "value": value})
    return value


def unique_sorted(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted(set(values)))


def chunks(values: Sequence[T], size: int) -> Iterator[Sequence[T]]:
    if size <= 0:
        raise ValueError("size must be positive")
    for index in range(0, len(values), size):
        yield values[index:index + size]


def require_mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationError("object required", details={"field": field})
    return value


def require_sequence(value: Any, field: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValidationError("array required", details={"field": field})
    return value


def clamp_text(value: Any, field: str, maximum: int, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ValidationError("string required", details={"field": field})
    text = value.strip()
    if not text and not allow_empty:
        raise ValidationError("non-empty string required", details={"field": field})
    if len(text) > maximum:
        raise ValidationError("string too long", details={"field": field, "maximum": maximum})
    return text


def version_key(value: str) -> tuple[int, int, int, int, str]:
    ensure_version(value)
    main, separator, suffix = value.partition("-")
    if not separator:
        main, plus, build = value.partition("+")
        suffix = build if plus else ""
    parts = [int(item) for item in main.split(".")]
    parts.extend([0] * (4 - len(parts)))
    return parts[0], parts[1], parts[2], parts[3], suffix


def in_version_range(version: str, minimum: str | None, maximum: str | None) -> bool:
    current = version_key(version)
    if minimum is not None and current < version_key(minimum):
        return False
    if maximum is not None and current > version_key(maximum):
        return False
    return True


def flatten_mapping(value: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in value.items():
        path = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(item, Mapping):
            result.update(flatten_mapping(item, path))
        else:
            result[path] = item
    return result
