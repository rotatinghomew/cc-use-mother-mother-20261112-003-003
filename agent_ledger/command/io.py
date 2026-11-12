from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Iterable, TextIO

from ..errors import ValidationError


def load_json(path: str) -> Any:
    text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValidationError(
            "invalid JSON input",
            details={"path": path, "line": exc.lineno, "column": exc.colno, "message": exc.msg},
        ) from exc


def load_json_lines(path: str) -> list[Any]:
    handle: TextIO
    close = False
    if path == "-":
        handle = sys.stdin
    else:
        handle = Path(path).open("r", encoding="utf-8")
        close = True
    values: list[Any] = []
    try:
        for number, line in enumerate(handle, 1):
            text = line.strip()
            if not text:
                continue
            try:
                values.append(json.loads(text))
            except json.JSONDecodeError as exc:
                raise ValidationError(
                    "invalid JSON line",
                    details={"path": path, "line": number, "column": exc.colno, "message": exc.msg},
                ) from exc
    finally:
        if close:
            handle.close()
    return values


def dump_json(value: Any, *, output: str | None = None, pretty: bool = True) -> None:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2 if pretty else None) + "\n"
    if output is None or output == "-":
        sys.stdout.write(text)
    else:
        destination = Path(output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")


def dump_json_lines(values: Iterable[Any], *, output: str | None = None) -> None:
    text = "".join(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n" for value in values)
    if output is None or output == "-":
        sys.stdout.write(text)
    else:
        destination = Path(output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")


def require_object(value: Any, label: str = "input") -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError(f"{label} must be a JSON object")
    return value


def require_array(value: Any, label: str = "input") -> list[Any]:
    if not isinstance(value, list):
        raise ValidationError(f"{label} must be a JSON array")
    return value
