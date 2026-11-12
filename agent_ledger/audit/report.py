from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ..declarations.parser import DeclarationParser
from ..models import DeclarationAction, DecisionStatus
from ..policy.evaluator import PolicyEvaluator
from ..temporal.index import TemporalDeclarationIndex
from ..temporal.store import LedgerStore
from ..util import format_time


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    subject_id: str
    message: str
    evidence: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "code": self.code,
            "subject_id": self.subject_id,
            "message": self.message,
            "evidence": self.evidence,
        }


class ComplianceReport:
    def __init__(self, store: LedgerStore, parser: DeclarationParser | None = None) -> None:
        self.store = store
        self.parser = parser or DeclarationParser()

    def generate(self, since: datetime | None = None) -> dict[str, Any]:
        index = TemporalDeclarationIndex.from_store(self.store, self.parser)
        evaluator = PolicyEvaluator(index)
        findings: list[Finding] = []
        status_counts: Counter[str] = Counter()
        reason_counts: Counter[str] = Counter()
        app_counts: dict[str, Counter[str]] = defaultdict(Counter)
        for declaration in index.all():
            findings.extend(self._declaration_findings(declaration, index))
        for payload in self.store.request_payloads(since=since):
            request = self.parser.parse_request(payload)
            decision = evaluator.evaluate(request, self.store.revision())
            status_counts[decision.status.value] += 1
            reason_counts.update(reason.code for reason in decision.reasons)
            app_counts[request.application_id][decision.status.value] += 1
            findings.extend(self._request_findings(request, decision))
        findings.sort(key=lambda item: (self._severity_rank(item.severity), item.code, item.subject_id))
        return {
            "scope": {"since": format_time(since), "ledger_revision": self.store.revision()},
            "status_counts": dict(sorted(status_counts.items())),
            "reason_counts": dict(sorted(reason_counts.items())),
            "application_counts": {key: dict(sorted(value.items())) for key, value in sorted(app_counts.items())},
            "finding_counts": dict(Counter(item.severity for item in findings)),
            "findings": [item.as_dict() for item in findings],
        }

    def _declaration_findings(self, declaration, index: TemporalDeclarationIndex) -> list[Finding]:
        result: list[Finding] = []
        if declaration.effective_until is None:
            result.append(Finding(
                "info", "open_ended_declaration", declaration.declaration_id,
                "declaration has no automatic expiry",
                {"effective_from": format_time(declaration.effective_from), "action": declaration.action.value},
            ))
        if declaration.application_id == "*" or declaration.agent_identity == "*":
            result.append(Finding(
                "medium", "broad_selector", declaration.declaration_id,
                "declaration uses a wildcard application or agent selector",
                {"application_id": declaration.application_id, "agent_identity": declaration.agent_identity},
            ))
        if not declaration.scope.regions:
            result.append(Finding(
                "low", "unbounded_region", declaration.declaration_id,
                "declaration applies in every region", {},
            ))
        device = declaration.scope.device
        if not any((device.manufacturers, device.models, device.os_families, device.min_security_patch, device.managed_only)):
            result.append(Finding(
                "low", "unbounded_device", declaration.declaration_id,
                "declaration does not constrain device posture", {},
            ))
        if declaration.inherited_from is not None:
            parent = index.get(declaration.inherited_from)
            if parent is None:
                result.append(Finding(
                    "high", "missing_parent", declaration.declaration_id,
                    "inherited declaration refers to a missing parent", {"parent": declaration.inherited_from},
                ))
            elif parent.action is DeclarationAction.DENY and declaration.action is DeclarationAction.GRANT:
                result.append(Finding(
                    "high", "grant_inherits_deny", declaration.declaration_id,
                    "grant inherits from a denial and cannot become effective", {"parent": parent.declaration_id},
                ))
        return result

    @staticmethod
    def _request_findings(request, decision) -> list[Finding]:
        result: list[Finding] = []
        codes = {reason.code for reason in decision.reasons}
        if decision.status is DecisionStatus.DENY and "no_active_declaration" in codes:
            result.append(Finding(
                "high", "undeclared_call", request.request_id,
                "call request has no active electronic declaration",
                {"application_id": request.application_id, "agent_identity": request.agent_identity, "capability": request.capability},
            ))
        if decision.status is DecisionStatus.DENY and "capability_out_of_scope" in codes:
            result.append(Finding(
                "high", "undeclared_capability", request.request_id,
                "application requested a capability outside its declared scope",
                {"capability": request.capability, "application_id": request.application_id},
            ))
        if "security_patch_too_old" in codes:
            result.append(Finding(
                "medium", "device_patch_noncompliance", request.request_id,
                "device security patch failed declaration constraints",
                {"security_patch": request.device.security_patch, "device_id": request.device.device_id},
            ))
        return result

    @staticmethod
    def _severity_rank(value: str) -> int:
        return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(value, 5)
