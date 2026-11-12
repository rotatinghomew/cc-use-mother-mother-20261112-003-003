from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

from ..models import CallRequest, Decision, DecisionStatus
from ..temporal.store import LedgerStore
from .evaluator import PolicyEvaluator


@dataclass(frozen=True)
class MatrixCell:
    key: tuple[str, ...]
    total: int
    allowed: int
    denied: int
    indeterminate: int
    reason_counts: dict[str, int]

    @property
    def allow_rate(self) -> float:
        return 0.0 if self.total == 0 else self.allowed / self.total

    def as_dict(self, dimensions: tuple[str, ...]) -> dict:
        return {
            "dimensions": dict(zip(dimensions, self.key)),
            "total": self.total,
            "allowed": self.allowed,
            "denied": self.denied,
            "indeterminate": self.indeterminate,
            "allow_rate": round(self.allow_rate, 6),
            "reason_counts": self.reason_counts,
        }


class PolicyMatrix:
    allowed_dimensions = {
        "developer_id", "application_id", "agent_identity", "capability", "region",
        "manufacturer", "model", "os_family", "managed", "status",
    }

    def __init__(self, evaluator: PolicyEvaluator, store: LedgerStore) -> None:
        self.evaluator = evaluator
        self.store = store

    def evaluate(self, requests: Iterable[CallRequest], dimensions: tuple[str, ...]) -> list[MatrixCell]:
        if not dimensions:
            dimensions = ("application_id", "capability")
        unknown = sorted(set(dimensions) - self.allowed_dimensions)
        if unknown:
            raise ValueError(f"unsupported matrix dimensions: {', '.join(unknown)}")
        revision = self.store.revision()
        buckets: dict[tuple[str, ...], list[Decision]] = defaultdict(list)
        for request in requests:
            decision = self.evaluator.evaluate(request, revision)
            key = tuple(self._dimension(dimension, request, decision) for dimension in dimensions)
            buckets[key].append(decision)
        cells = [self._cell(key, decisions) for key, decisions in buckets.items()]
        cells.sort(key=lambda item: item.key)
        return cells

    def compare_times(self, requests: Iterable[CallRequest], first: datetime, second: datetime) -> dict:
        revision = self.store.revision()
        changed: list[dict] = []
        unchanged = 0
        for request in requests:
            first_request = CallRequest(
                request.request_id + "@first", request.developer_id, request.application_id, request.application_version,
                request.agent_identity, request.capability, request.region, first, request.device, request.attributes,
            )
            second_request = CallRequest(
                request.request_id + "@second", request.developer_id, request.application_id, request.application_version,
                request.agent_identity, request.capability, request.region, second, request.device, request.attributes,
            )
            before = self.evaluator.evaluate(first_request, revision)
            after = self.evaluator.evaluate(second_request, revision)
            if before.status is after.status and [item.code for item in before.reasons] == [item.code for item in after.reasons]:
                unchanged += 1
            else:
                changed.append({
                    "request_id": request.request_id,
                    "first": before.as_dict(),
                    "second": after.as_dict(),
                })
        return {"first": first.isoformat(), "second": second.isoformat(), "unchanged": unchanged, "changed": changed}

    @staticmethod
    def _dimension(name: str, request: CallRequest, decision: Decision) -> str:
        if name == "status":
            return decision.status.value
        if name == "manufacturer":
            return request.device.manufacturer
        if name == "model":
            return request.device.model
        if name == "os_family":
            return request.device.os_family
        if name == "managed":
            return "managed" if request.device.managed else "unmanaged"
        return str(getattr(request, name))

    @staticmethod
    def _cell(key: tuple[str, ...], decisions: list[Decision]) -> MatrixCell:
        status_counts = Counter(item.status for item in decisions)
        reason_counts = Counter(reason.code for item in decisions for reason in item.reasons)
        return MatrixCell(
            key=key,
            total=len(decisions),
            allowed=status_counts[DecisionStatus.ALLOW],
            denied=status_counts[DecisionStatus.DENY],
            indeterminate=status_counts[DecisionStatus.INDETERMINATE],
            reason_counts=dict(sorted(reason_counts.items())),
        )
