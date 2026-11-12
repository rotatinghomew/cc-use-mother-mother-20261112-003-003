from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..declarations.parser import DeclarationParser
from ..errors import LedgerError
from ..policy.evaluator import PolicyEvaluator
from ..temporal.index import TemporalDeclarationIndex
from ..temporal.store import LedgerStore
from ..util import utc_now


@dataclass(frozen=True)
class ReconcileOutcome:
    processed: int
    changed: int
    unchanged: int
    failed: int
    details: tuple[dict[str, Any], ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "processed": self.processed,
            "changed": self.changed,
            "unchanged": self.unchanged,
            "failed": self.failed,
            "details": list(self.details),
        }


class Reconciler:
    def __init__(self, store: LedgerStore, parser: DeclarationParser | None = None) -> None:
        self.store = store
        self.parser = parser or DeclarationParser()

    def run(self, limit: int = 100) -> ReconcileOutcome:
        index = TemporalDeclarationIndex.from_store(self.store, self.parser)
        evaluator = PolicyEvaluator(index)
        revision = self.store.revision()
        processed = changed = unchanged = failed = 0
        details: list[dict[str, Any]] = []
        for queued in self.store.queued_recomputations(limit):
            request_id = queued["request_id"]
            processed += 1
            try:
                request = self.parser.parse_request(self.store.get_request_payload(request_id))
                previous = self.store.current_decision(request_id)
                current = evaluator.evaluate(request, revision, decided_at=utc_now())
                equivalent = self._equivalent(previous, current)
                if equivalent:
                    unchanged += 1
                else:
                    self.store.save_decision(current)
                    changed += 1
                self.store.record_audit(
                    "request_reconciled",
                    request_id,
                    {
                        "cause_event_id": queued["cause_event_id"],
                        "previous_decision_id": None if previous is None else previous.decision_id,
                        "current_decision_id": current.decision_id,
                        "changed": not equivalent,
                        "previous_status": None if previous is None else previous.status.value,
                        "current_status": current.status.value,
                    },
                )
                self.store.complete_recompute(request_id)
                details.append({"request_id": request_id, "changed": not equivalent, "decision": current.as_dict()})
            except Exception as exc:
                failed += 1
                self.store.fail_recompute(request_id, str(exc))
                if isinstance(exc, LedgerError):
                    error = exc.as_dict()
                else:
                    error = {"code": "unexpected_reconcile_error", "message": str(exc), "details": {}}
                details.append({"request_id": request_id, "changed": False, "error": error})
        return ReconcileOutcome(processed, changed, unchanged, failed, tuple(details))

    def rebuild_all(self) -> ReconcileOutcome:
        index = TemporalDeclarationIndex.from_store(self.store, self.parser)
        evaluator = PolicyEvaluator(index)
        revision = self.store.revision()
        processed = changed = unchanged = failed = 0
        details: list[dict[str, Any]] = []
        for payload in self.store.request_payloads():
            request_id = payload.get("request_id", "unknown")
            processed += 1
            try:
                request = self.parser.parse_request(payload)
                previous = self.store.current_decision(request.request_id)
                current = evaluator.evaluate(request, revision)
                equivalent = self._equivalent(previous, current)
                if equivalent:
                    unchanged += 1
                else:
                    self.store.save_decision(current)
                    changed += 1
                details.append({"request_id": request.request_id, "changed": not equivalent, "decision_id": current.decision_id})
            except Exception as exc:
                failed += 1
                details.append({"request_id": request_id, "changed": False, "error": str(exc)})
        self.store.record_audit(
            "full_rebuild",
            "ledger",
            {"processed": processed, "changed": changed, "unchanged": unchanged, "failed": failed, "revision": revision},
        )
        return ReconcileOutcome(processed, changed, unchanged, failed, tuple(details))

    @staticmethod
    def _equivalent(first, second) -> bool:
        if first is None:
            return False
        return (
            first.status is second.status
            and [item.code for item in first.reasons] == [item.code for item in second.reasons]
            and first.matched_declarations == second.matched_declarations
        )
