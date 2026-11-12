from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable, Mapping

from ..declarations.parser import DeclarationParser
from ..errors import LedgerError, SignatureError, ValidationError
from ..models import BatchQuery, BatchResult, CallRequest, Decision, EventKind, SignedEnvelope
from ..policy.evaluator import PolicyEvaluator
from ..signatures.envelope import LocalKeyring
from ..temporal.index import TemporalDeclarationIndex
from ..temporal.store import LedgerStore
from ..util import parse_time, stable_id, utc_now


@dataclass(frozen=True)
class IngestResult:
    event_id: str
    entity_id: str
    inserted: bool
    late: bool
    revision: int
    queued_recomputations: int = 0
    decision: Decision | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "entity_id": self.entity_id,
            "inserted": self.inserted,
            "late": self.late,
            "revision": self.revision,
            "queued_recomputations": self.queued_recomputations,
            "decision": None if self.decision is None else self.decision.as_dict(),
        }


class LedgerService:
    def __init__(self, store: LedgerStore, keyring: LocalKeyring, parser: DeclarationParser | None = None) -> None:
        self.store = store
        self.keyring = keyring
        self.parser = parser or DeclarationParser()
        self.index = TemporalDeclarationIndex.from_store(store, self.parser)
        self.evaluator = PolicyEvaluator(self.index)

    def refresh(self) -> None:
        self.index = TemporalDeclarationIndex.from_store(self.store, self.parser)
        self.evaluator = PolicyEvaluator(self.index)

    def ingest_signed_declaration(
        self,
        envelope_value: SignedEnvelope | Mapping[str, Any],
        *,
        event_id: str | None = None,
        received_at: datetime | None = None,
    ) -> IngestResult:
        envelope = envelope_value if isinstance(envelope_value, SignedEnvelope) else self.keyring.parse_envelope(envelope_value)
        self.keyring.verify_or_raise(envelope)
        declaration = self.parser.parse(envelope.payload)
        if envelope.signed_at > declaration.issued_at:
            skew = (envelope.signed_at - declaration.issued_at).total_seconds()
            if skew > 86400:
                raise SignatureError("signature timestamp is too far after declaration issuance", details={"skew_seconds": skew})
        actual_received = received_at or utc_now()
        actual_event_id = event_id or stable_id("evt", {"kind": "declaration", "declaration_id": declaration.declaration_id, "signature": envelope.signature})
        event = self.store.event_for(
            EventKind.WITHDRAWAL if declaration.action.value == "withdraw" else EventKind.DECLARATION,
            declaration.declaration_id,
            declaration.effective_from,
            declaration.as_payload(),
            actual_event_id,
            actual_received,
        )
        with self.store.transaction() as connection:
            stored_event, inserted_event = self.store.append_event(event, connection)
            inserted_declaration = self.store.save_declaration(stored_event, connection) if inserted_event else False
            queued = 0
            if inserted_declaration:
                affected = self.store.affected_request_ids(
                    declaration.effective_from, declaration.effective_until, declaration.developer_id,
                    declaration.application_id if declaration.application_id != "*" else declaration.application_id,
                    declaration.agent_identity if declaration.agent_identity != "*" else declaration.agent_identity,
                )
                if declaration.application_id == "*" or declaration.agent_identity == "*":
                    affected = self._affected_wildcard_requests(declaration)
                queued = self.store.queue_recompute(affected, stored_event.event_id, connection)
                self.store.record_audit(
                    "declaration_ingested",
                    declaration.declaration_id,
                    {
                        "event_id": stored_event.event_id,
                        "action": declaration.action.value,
                        "signature_key_id": envelope.key_id,
                        "signature_fingerprint": self.keyring.fingerprint(envelope.key_id),
                        "late": stored_event.is_late,
                        "affected_requests": len(affected),
                    },
                    connection,
                )
        if inserted_declaration:
            self.index.add(declaration)
        return IngestResult(
            event_id=stored_event.event_id,
            entity_id=declaration.declaration_id,
            inserted=inserted_declaration,
            late=stored_event.is_late,
            revision=self.store.revision(),
            queued_recomputations=queued,
        )

    def ingest_request(
        self,
        request_value: CallRequest | Mapping[str, Any],
        *,
        event_id: str | None = None,
        received_at: datetime | None = None,
        persist_decision: bool = True,
    ) -> IngestResult:
        request = request_value if isinstance(request_value, CallRequest) else self.parser.parse_request(request_value)
        actual_received = received_at or utc_now()
        actual_event_id = event_id or stable_id("evt", {"kind": "request", "request_id": request.request_id})
        event = self.store.event_for(
            EventKind.REQUEST, request.request_id, request.requested_at, request.as_dict(), actual_event_id, actual_received
        )
        with self.store.transaction() as connection:
            stored_event, inserted_event = self.store.append_event(event, connection)
            inserted_request = self.store.save_request(stored_event, connection) if inserted_event else False
            revision = self.store.revision(connection)
            decision = self.evaluator.evaluate(request, revision)
            if persist_decision:
                self.store.save_decision(decision, connection)
            self.store.record_audit(
                "request_evaluated",
                request.request_id,
                {
                    "event_id": stored_event.event_id,
                    "inserted": inserted_request,
                    "late": stored_event.is_late,
                    "status": decision.status.value,
                    "decision_id": decision.decision_id,
                    "reason_codes": [reason.code for reason in decision.reasons],
                },
                connection,
            )
        return IngestResult(
            event_id=stored_event.event_id,
            entity_id=request.request_id,
            inserted=inserted_request,
            late=stored_event.is_late,
            revision=revision,
            decision=decision,
        )

    def evaluate(self, request_value: CallRequest | Mapping[str, Any]) -> Decision:
        request = request_value if isinstance(request_value, CallRequest) else self.parser.parse_request(request_value)
        return self.evaluator.evaluate(request, self.store.revision())

    def batch_evaluate(self, query: BatchQuery | Iterable[CallRequest | Mapping[str, Any]]) -> BatchResult:
        if isinstance(query, BatchQuery):
            values: Iterable[CallRequest | Mapping[str, Any]] = query.requests
            fail_fast = query.fail_fast
        else:
            values = query
            fail_fast = False
        decisions: list[Decision] = []
        errors: list[dict[str, Any]] = []
        revision = self.store.revision()
        for index, value in enumerate(values):
            try:
                request = value if isinstance(value, CallRequest) else self.parser.parse_request(value)
                decisions.append(self.evaluator.evaluate(request, revision))
            except LedgerError as exc:
                errors.append({"index": index, **exc.as_dict()})
                if fail_fast:
                    break
        return BatchResult(tuple(decisions), tuple(errors))

    def ingest_batch_requests(
        self,
        values: Iterable[CallRequest | Mapping[str, Any]],
        *,
        atomic: bool = False,
    ) -> dict[str, Any]:
        values = list(values)
        if atomic:
            parsed = [value if isinstance(value, CallRequest) else self.parser.parse_request(value) for value in values]
            return self._ingest_atomic_requests(parsed)
        results: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        for index, value in enumerate(values):
            try:
                results.append(self.ingest_request(value).as_dict())
            except LedgerError as exc:
                errors.append({"index": index, **exc.as_dict()})
        return {"atomic": False, "results": results, "errors": errors}

    def _ingest_atomic_requests(self, requests: list[CallRequest]) -> dict[str, Any]:
        results: list[dict[str, Any]] = []
        now = utc_now()
        with self.store.transaction() as connection:
            revision = self.store.revision(connection)
            for request in requests:
                event_id = stable_id("evt", {"kind": "request", "request_id": request.request_id})
                event = self.store.event_for(EventKind.REQUEST, request.request_id, request.requested_at, request.as_dict(), event_id, now)
                stored, inserted_event = self.store.append_event(event, connection)
                inserted_request = self.store.save_request(stored, connection) if inserted_event else False
                decision = self.evaluator.evaluate(request, revision)
                self.store.save_decision(decision, connection)
                self.store.record_audit(
                    "request_evaluated", request.request_id,
                    {"event_id": stored.event_id, "inserted": inserted_request, "status": decision.status.value, "atomic_batch": True},
                    connection,
                )
                results.append(IngestResult(stored.event_id, request.request_id, inserted_request, stored.is_late, revision, decision=decision).as_dict())
        return {"atomic": True, "results": results, "errors": []}

    def _affected_wildcard_requests(self, declaration) -> list[str]:
        result: list[str] = []
        for payload in self.store.request_payloads(since=declaration.effective_from):
            requested_at = parse_time(payload["requested_at"])
            if declaration.effective_until is not None and requested_at >= declaration.effective_until:
                continue
            if payload["developer_id"] != declaration.developer_id:
                continue
            if declaration.application_id != "*" and payload["application_id"] != declaration.application_id:
                continue
            if declaration.agent_identity != "*" and payload["agent_identity"] != declaration.agent_identity:
                continue
            result.append(payload["request_id"])
        return result
