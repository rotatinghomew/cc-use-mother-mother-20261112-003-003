from __future__ import annotations

import csv
import io
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from ..declarations.parser import DeclarationParser
from ..models import DecisionStatus
from ..policy.evaluator import PolicyEvaluator
from ..temporal.index import TemporalDeclarationIndex
from ..temporal.store import LedgerStore
from ..util import canonical_json, format_time, sha256_hex, utc_now


class AuditExporter:
    def __init__(self, store: LedgerStore, parser: DeclarationParser | None = None) -> None:
        self.store = store
        self.parser = parser or DeclarationParser()

    def snapshot(self) -> dict[str, Any]:
        declarations = self.store.declaration_payloads()
        requests = self.store.request_payloads()
        decision_rows = []
        status_counts: Counter[str] = Counter()
        reason_counts: Counter[str] = Counter()
        for request in requests:
            decision = self.store.current_decision(request["request_id"])
            if decision is None:
                continue
            decision_rows.append(decision.as_dict())
            status_counts[decision.status.value] += 1
            reason_counts.update(reason.code for reason in decision.reasons)
        result = {
            "generated_at": format_time(utc_now()),
            "ledger_revision": self.store.revision(),
            "counts": self.store.counts(),
            "decision_status_counts": dict(sorted(status_counts.items())),
            "reason_counts": dict(sorted(reason_counts.items())),
            "declarations": declarations,
            "requests": requests,
            "decisions": decision_rows,
            "audit_records": self.store.audit_records(),
        }
        result["snapshot_hash"] = sha256_hex(canonical_json(result))
        return result

    def export_json(self, path: str | Path, *, pretty: bool = True) -> dict[str, Any]:
        snapshot = self.snapshot()
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(snapshot, ensure_ascii=False, sort_keys=True, indent=2 if pretty else None)
        destination.write_text(text + "\n", encoding="utf-8")
        return {"path": str(destination), "bytes": destination.stat().st_size, "snapshot_hash": snapshot["snapshot_hash"]}

    def export_decisions_csv(self, path: str | Path) -> dict[str, Any]:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        rows: list[dict[str, Any]] = []
        for request_payload in self.store.request_payloads():
            request = self.parser.parse_request(request_payload)
            decision = self.store.current_decision(request.request_id)
            if decision is None:
                continue
            rows.append({
                "request_id": request.request_id,
                "requested_at": format_time(request.requested_at),
                "developer_id": request.developer_id,
                "application_id": request.application_id,
                "application_version": request.application_version,
                "agent_identity": request.agent_identity,
                "capability": request.capability,
                "region": request.region,
                "device_id": request.device.device_id,
                "manufacturer": request.device.manufacturer,
                "model": request.device.model,
                "os_family": request.device.os_family,
                "managed": str(request.device.managed).lower(),
                "decision_id": decision.decision_id,
                "status": decision.status.value,
                "reason_codes": "|".join(reason.code for reason in decision.reasons),
                "reason_messages": "|".join(reason.message for reason in decision.reasons),
                "matched_declarations": "|".join(decision.matched_declarations),
                "ledger_revision": decision.ledger_revision,
            })
        fields = list(rows[0]) if rows else ["request_id", "status"]
        with destination.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
        return {"path": str(destination), "rows": len(rows), "bytes": destination.stat().st_size}

    def declaration_timeline(self, developer_id: str, application_id: str, agent_identity: str) -> list[dict[str, Any]]:
        index = TemporalDeclarationIndex.from_store(self.store, self.parser)
        result = []
        for entry in index.timeline(developer_id, application_id, agent_identity):
            declaration = entry.declaration
            result.append({
                "declaration_id": declaration.declaration_id,
                "action": declaration.action.value,
                "start": format_time(entry.start),
                "end": format_time(entry.end),
                "priority": declaration.priority,
                "capabilities": list(declaration.scope.capabilities),
                "regions": list(declaration.scope.regions),
                "inherited_from": declaration.inherited_from,
            })
        return result

    def compliance_summary(self, since: datetime | None = None) -> dict[str, Any]:
        index = TemporalDeclarationIndex.from_store(self.store, self.parser)
        evaluator = PolicyEvaluator(index)
        revision = self.store.revision()
        status_counts: Counter[str] = Counter()
        reason_counts: Counter[str] = Counter()
        capability_counts: Counter[str] = Counter()
        application_counts: dict[str, Counter[str]] = {}
        evaluated = 0
        for payload in self.store.request_payloads(since=since):
            request = self.parser.parse_request(payload)
            decision = evaluator.evaluate(request, revision)
            evaluated += 1
            status_counts[decision.status.value] += 1
            capability_counts[request.capability] += 1
            reason_counts.update(reason.code for reason in decision.reasons)
            application_counts.setdefault(request.application_id, Counter())[decision.status.value] += 1
        denied = status_counts[DecisionStatus.DENY.value]
        return {
            "since": format_time(since),
            "evaluated": evaluated,
            "status_counts": dict(sorted(status_counts.items())),
            "denial_rate": 0.0 if evaluated == 0 else round(denied / evaluated, 6),
            "reason_counts": dict(sorted(reason_counts.items(), key=lambda item: (-item[1], item[0]))),
            "capability_counts": dict(sorted(capability_counts.items(), key=lambda item: (-item[1], item[0]))),
            "applications": {key: dict(sorted(value.items())) for key, value in sorted(application_counts.items())},
        }

    def verify_snapshot(self, value: dict[str, Any]) -> bool:
        supplied = value.get("snapshot_hash")
        if not isinstance(supplied, str):
            return False
        payload = dict(value)
        payload.pop("snapshot_hash", None)
        return sha256_hex(canonical_json(payload)) == supplied

    def json_lines(self, records: Iterable[dict[str, Any]]) -> str:
        buffer = io.StringIO()
        for record in records:
            buffer.write(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
            buffer.write("\n")
        return buffer.getvalue()
