from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Iterable

from .util import format_time, stable_id, unique_sorted


class DeclarationAction(str, Enum):
    GRANT = "grant"
    DENY = "deny"
    WITHDRAW = "withdraw"


class DecisionStatus(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    INDETERMINATE = "indeterminate"


class EventKind(str, Enum):
    DECLARATION = "declaration"
    WITHDRAWAL = "withdrawal"
    REQUEST = "request"


@dataclass(frozen=True)
class VersionRange:
    minimum: str | None = None
    maximum: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"minimum": self.minimum, "maximum": self.maximum}


@dataclass(frozen=True)
class DeviceConstraint:
    manufacturers: tuple[str, ...] = ()
    models: tuple[str, ...] = ()
    os_families: tuple[str, ...] = ()
    min_security_patch: str | None = None
    managed_only: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "manufacturers": list(self.manufacturers),
            "models": list(self.models),
            "os_families": list(self.os_families),
            "min_security_patch": self.min_security_patch,
            "managed_only": self.managed_only,
        }


@dataclass(frozen=True)
class Scope:
    capabilities: tuple[str, ...]
    regions: tuple[str, ...] = ()
    version_range: VersionRange = field(default_factory=VersionRange)
    device: DeviceConstraint = field(default_factory=DeviceConstraint)

    def as_dict(self) -> dict[str, Any]:
        return {
            "capabilities": list(self.capabilities),
            "regions": list(self.regions),
            "version_range": self.version_range.as_dict(),
            "device": self.device.as_dict(),
        }


@dataclass(frozen=True)
class Declaration:
    declaration_id: str
    developer_id: str
    application_id: str
    agent_identity: str
    action: DeclarationAction
    scope: Scope
    effective_from: datetime
    effective_until: datetime | None
    priority: int
    inherited_from: str | None
    reason: str
    issued_at: datetime
    nonce: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_payload(self) -> dict[str, Any]:
        return {
            "declaration_id": self.declaration_id,
            "developer_id": self.developer_id,
            "application_id": self.application_id,
            "agent_identity": self.agent_identity,
            "action": self.action.value,
            "scope": self.scope.as_dict(),
            "effective_from": format_time(self.effective_from),
            "effective_until": format_time(self.effective_until),
            "priority": self.priority,
            "inherited_from": self.inherited_from,
            "reason": self.reason,
            "issued_at": format_time(self.issued_at),
            "nonce": self.nonce,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class SignedEnvelope:
    key_id: str
    algorithm: str
    payload: dict[str, Any]
    signature: str
    signed_at: datetime

    def as_dict(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "payload": self.payload,
            "signature": self.signature,
            "signed_at": format_time(self.signed_at),
        }


@dataclass(frozen=True)
class DeviceContext:
    device_id: str
    manufacturer: str
    model: str
    os_family: str
    security_patch: str
    managed: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "manufacturer": self.manufacturer,
            "model": self.model,
            "os_family": self.os_family,
            "security_patch": self.security_patch,
            "managed": self.managed,
        }


@dataclass(frozen=True)
class CallRequest:
    request_id: str
    developer_id: str
    application_id: str
    application_version: str
    agent_identity: str
    capability: str
    region: str
    requested_at: datetime
    device: DeviceContext
    attributes: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "developer_id": self.developer_id,
            "application_id": self.application_id,
            "application_version": self.application_version,
            "agent_identity": self.agent_identity,
            "capability": self.capability,
            "region": self.region,
            "requested_at": format_time(self.requested_at),
            "device": self.device.as_dict(),
            "attributes": self.attributes,
        }


@dataclass(frozen=True)
class Reason:
    code: str
    message: str
    declaration_id: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "declaration_id": self.declaration_id,
            "details": self.details,
        }


@dataclass(frozen=True)
class Decision:
    request_id: str
    status: DecisionStatus
    decided_at: datetime
    policy_time: datetime
    reasons: tuple[Reason, ...]
    matched_declarations: tuple[str, ...]
    ledger_revision: int
    decision_id: str = ""

    def __post_init__(self) -> None:
        if not self.decision_id:
            payload = {
                "request_id": self.request_id,
                "status": self.status.value,
                "policy_time": format_time(self.policy_time),
                "matched": list(self.matched_declarations),
                "revision": self.ledger_revision,
            }
            object.__setattr__(self, "decision_id", stable_id("dec", payload))

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "request_id": self.request_id,
            "status": self.status.value,
            "decided_at": format_time(self.decided_at),
            "policy_time": format_time(self.policy_time),
            "reasons": [reason.as_dict() for reason in self.reasons],
            "matched_declarations": list(self.matched_declarations),
            "ledger_revision": self.ledger_revision,
        }


@dataclass(frozen=True)
class LedgerEvent:
    event_id: str
    kind: EventKind
    entity_id: str
    occurred_at: datetime
    received_at: datetime
    payload: dict[str, Any]
    content_hash: str
    sequence: int = 0

    @property
    def is_late(self) -> bool:
        return self.received_at > self.occurred_at

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "kind": self.kind.value,
            "entity_id": self.entity_id,
            "occurred_at": format_time(self.occurred_at),
            "received_at": format_time(self.received_at),
            "payload": self.payload,
            "content_hash": self.content_hash,
            "sequence": self.sequence,
            "is_late": self.is_late,
        }


@dataclass(frozen=True)
class BatchQuery:
    requests: tuple[CallRequest, ...]
    explain: bool = True
    fail_fast: bool = False


@dataclass(frozen=True)
class BatchResult:
    decisions: tuple[Decision, ...]
    errors: tuple[dict[str, Any], ...]

    @property
    def allowed(self) -> int:
        return sum(item.status is DecisionStatus.ALLOW for item in self.decisions)

    @property
    def denied(self) -> int:
        return sum(item.status is DecisionStatus.DENY for item in self.decisions)

    def as_dict(self) -> dict[str, Any]:
        return {
            "summary": {
                "total": len(self.decisions) + len(self.errors),
                "allowed": self.allowed,
                "denied": self.denied,
                "errors": len(self.errors),
            },
            "decisions": [item.as_dict() for item in self.decisions],
            "errors": list(self.errors),
        }


def merge_capabilities(items: Iterable[Declaration]) -> tuple[str, ...]:
    return unique_sorted(capability for item in items for capability in item.scope.capabilities)
