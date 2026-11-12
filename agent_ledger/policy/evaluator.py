from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

from ..errors import PolicyError
from ..models import CallRequest, Decision, DecisionStatus, Declaration, DeclarationAction, Reason
from ..temporal.index import TemporalDeclarationIndex
from ..util import utc_now
from .matchers import ConstraintMatcher, MatchResult


@dataclass(frozen=True)
class CandidateEvaluation:
    declaration: Declaration
    match: MatchResult
    inherited_valid: bool
    inheritance_reason: str | None

    @property
    def applicable(self) -> bool:
        return self.match.matched and self.inherited_valid


class PolicyEvaluator:
    def __init__(self, index: TemporalDeclarationIndex, matcher: ConstraintMatcher | None = None) -> None:
        self.index = index
        self.matcher = matcher or ConstraintMatcher()

    def evaluate(self, request: CallRequest, ledger_revision: int, *, decided_at: datetime | None = None) -> Decision:
        candidates = self.index.active(
            request.developer_id, request.application_id, request.agent_identity, request.requested_at
        )
        evaluated = tuple(self._evaluate_candidate(item, request) for item in candidates)
        applicable = [item for item in evaluated if item.applicable and item.declaration.action is not DeclarationAction.WITHDRAW]
        if not applicable:
            reasons = self._no_match_reasons(evaluated)
            return Decision(
                request_id=request.request_id,
                status=DecisionStatus.DENY,
                decided_at=decided_at or utc_now(),
                policy_time=request.requested_at,
                reasons=tuple(reasons),
                matched_declarations=(),
                ledger_revision=ledger_revision,
            )
        winners = self._winning_tier(applicable)
        status, reasons = self._resolve(winners)
        return Decision(
            request_id=request.request_id,
            status=status,
            decided_at=decided_at or utc_now(),
            policy_time=request.requested_at,
            reasons=tuple(reasons),
            matched_declarations=tuple(item.declaration.declaration_id for item in winners),
            ledger_revision=ledger_revision,
        )

    def explain_candidates(self, request: CallRequest) -> list[dict]:
        candidates = self.index.active(request.developer_id, request.application_id, request.agent_identity, request.requested_at)
        return [
            {
                "declaration_id": result.declaration.declaration_id,
                "action": result.declaration.action.value,
                "priority": result.declaration.priority,
                "specificity": self.index.specificity(result.declaration),
                "match": result.match.as_dict(),
                "inherited_valid": result.inherited_valid,
                "inheritance_reason": result.inheritance_reason,
            }
            for result in (self._evaluate_candidate(item, request) for item in candidates)
        ]

    def _evaluate_candidate(self, declaration: Declaration, request: CallRequest) -> CandidateEvaluation:
        match = self.matcher.match(declaration, request)
        inherited_valid, reason = self._inheritance_valid(declaration, request)
        return CandidateEvaluation(declaration, match, inherited_valid, reason)

    def _inheritance_valid(self, declaration: Declaration, request: CallRequest) -> tuple[bool, str | None]:
        if declaration.inherited_from is None:
            return True, None
        try:
            chain = self.index.chain(declaration)
        except PolicyError as exc:
            return False, exc.message
        for parent in chain[1:]:
            if not (parent.effective_from <= request.requested_at and (parent.effective_until is None or request.requested_at < parent.effective_until)):
                return False, f"parent {parent.declaration_id} is not effective at request time"
            result = self.matcher.match(parent, request)
            if not result.matched:
                failure = result.first_failure
                return False, f"parent {parent.declaration_id} does not cover request: {failure.code if failure else 'unknown'}"
            if parent.action is DeclarationAction.DENY:
                return False, f"parent {parent.declaration_id} explicitly denies the request"
        return True, None

    @staticmethod
    def _winning_tier(applicable: list[CandidateEvaluation]) -> list[CandidateEvaluation]:
        ranked = sorted(applicable, key=lambda item: TemporalDeclarationIndex.rank(item.declaration), reverse=True)
        first = ranked[0]
        first_key = (first.declaration.priority, TemporalDeclarationIndex.specificity(first.declaration))
        return [
            item for item in ranked
            if (item.declaration.priority, TemporalDeclarationIndex.specificity(item.declaration)) == first_key
        ]

    @staticmethod
    def _resolve(winners: list[CandidateEvaluation]) -> tuple[DecisionStatus, list[Reason]]:
        denies = [item.declaration for item in winners if item.declaration.action is DeclarationAction.DENY]
        grants = [item.declaration for item in winners if item.declaration.action is DeclarationAction.GRANT]
        if denies:
            reasons = [
                Reason(
                    "explicit_denial",
                    declaration.reason or "an applicable electronic declaration explicitly denies this call",
                    declaration.declaration_id,
                    {"priority": declaration.priority},
                )
                for declaration in denies
            ]
            if grants:
                reasons.append(
                    Reason(
                        "deny_breaks_tie",
                        "grant and deny declarations had equal priority and specificity; deny wins",
                        details={"grant_ids": [item.declaration_id for item in grants]},
                    )
                )
            return DecisionStatus.DENY, reasons
        if grants:
            return DecisionStatus.ALLOW, [
                Reason(
                    "declared_consent",
                    declaration.reason or "developer declaration authorizes the call",
                    declaration.declaration_id,
                    {"priority": declaration.priority},
                )
                for declaration in grants
            ]
        return DecisionStatus.INDETERMINATE, [Reason("policy_resolution_failed", "no grant or deny remained after policy resolution")]

    @staticmethod
    def _no_match_reasons(evaluated: Iterable[CandidateEvaluation]) -> list[Reason]:
        evaluated = list(evaluated)
        if not evaluated:
            return [Reason("no_active_declaration", "no electronic declaration was active at the request time")]
        reasons: list[Reason] = []
        seen: set[tuple[str, str | None]] = set()
        for candidate in evaluated:
            if not candidate.inherited_valid:
                key = ("invalid_inheritance", candidate.declaration.declaration_id)
                if key not in seen:
                    reasons.append(Reason("invalid_inheritance", candidate.inheritance_reason or "inheritance requirements failed", candidate.declaration.declaration_id))
                    seen.add(key)
            for failure in candidate.match.failures:
                key = (failure.code, candidate.declaration.declaration_id)
                if key in seen:
                    continue
                reasons.append(Reason(failure.code, failure.message, candidate.declaration.declaration_id, {"expected": failure.expected, "actual": failure.actual, "field": failure.field}))
                seen.add(key)
            if len(reasons) >= 8:
                break
        return reasons or [Reason("not_authorized", "active declarations do not authorize this request")]
