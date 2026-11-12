from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class LedgerError(Exception):
    code = "ledger_error"

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def as_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, "details": self.details}


class ValidationError(LedgerError):
    code = "validation_error"


class SignatureError(LedgerError):
    code = "signature_error"


class ConflictError(LedgerError):
    code = "conflict_error"


class NotFoundError(LedgerError):
    code = "not_found"


class StorageError(LedgerError):
    code = "storage_error"


class PolicyError(LedgerError):
    code = "policy_error"


@dataclass(frozen=True)
class FieldIssue:
    field: str
    reason: str
    value: Any = None

    def as_dict(self) -> dict[str, Any]:
        return {"field": self.field, "reason": self.reason, "value": self.value}


def require(condition: bool, message: str, **details: Any) -> None:
    if not condition:
        raise ValidationError(message, details=details)


def collect_issues(items: list[FieldIssue]) -> None:
    if items:
        raise ValidationError(
            "input contains invalid fields",
            details={"issues": [item.as_dict() for item in items]},
        )
