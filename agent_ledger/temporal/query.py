from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Iterable

from ..declarations.catalog import DeclarationCatalog
from ..declarations.parser import DeclarationParser
from ..models import CallRequest, DecisionStatus
from ..policy.evaluator import PolicyEvaluator
from ..temporal.index import TemporalDeclarationIndex
from ..temporal.store import LedgerStore
from ..util import format_time, parse_time


@dataclass(frozen=True)
class TimeWindow:
    start: datetime
    end: datetime

    def contains(self, value: datetime) -> bool:
        return self.start <= value < self.end

    def as_dict(self) -> dict[str, Any]:
        return {"start": format_time(self.start), "end": format_time(self.end)}


class TemporalQueryEngine:
    def __init__(self, store: LedgerStore, parser: DeclarationParser | None = None) -> None:
        self.store = store
        self.parser = parser or DeclarationParser()

    def decision_at(self, request_id: str, policy_time: datetime | None = None) -> dict[str, Any]:
        payload = self.store.get_request_payload(request_id)
        request = self.parser.parse_request(payload)
        if policy_time is not None:
            request = CallRequest(
                request.request_id, request.developer_id, request.application_id, request.application_version,
                request.agent_identity, request.capability, request.region, policy_time, request.device, request.attributes,
            )
        index = TemporalDeclarationIndex.from_store(self.store, self.parser)
        evaluator = PolicyEvaluator(index)
        decision = evaluator.evaluate(request, self.store.revision())
        return {
            "request": request.as_dict(),
            "decision": decision.as_dict(),
            "candidates": evaluator.explain_candidates(request),
        }

    def decision_diff(self, request_id: str, first: datetime, second: datetime) -> dict[str, Any]:
        before = self.decision_at(request_id, first)
        after = self.decision_at(request_id, second)
        before_decision = before["decision"]
        after_decision = after["decision"]
        return {
            "request_id": request_id,
            "first_time": format_time(first),
            "second_time": format_time(second),
            "status_changed": before_decision["status"] != after_decision["status"],
            "reason_codes_added": sorted(
                {item["code"] for item in after_decision["reasons"]} - {item["code"] for item in before_decision["reasons"]}
            ),
            "reason_codes_removed": sorted(
                {item["code"] for item in before_decision["reasons"]} - {item["code"] for item in after_decision["reasons"]}
            ),
            "first": before,
            "second": after,
        }

    def request_history(self, request_id: str) -> dict[str, Any]:
        request = self.store.get_request_payload(request_id)
        decisions = [item.as_dict() for item in self.store.decision_history(request_id)]
        audit = self.store.audit_records(request_id)
        return {
            "request": request,
            "decisions": decisions,
            "audit_records": audit,
            "changed_count": max(0, len(decisions) - 1),
        }

    def application_timeline(
        self,
        developer_id: str,
        application_id: str,
        start: datetime,
        end: datetime,
        bucket: timedelta = timedelta(days=1),
    ) -> list[dict[str, Any]]:
        if bucket.total_seconds() <= 0:
            raise ValueError("bucket must be positive")
        requests = [
            self.parser.parse_request(payload) for payload in self.store.request_payloads(since=start)
            if payload["developer_id"] == developer_id and payload["application_id"] == application_id
        ]
        index = TemporalDeclarationIndex.from_store(self.store, self.parser)
        evaluator = PolicyEvaluator(index)
        revision = self.store.revision()
        result: list[dict[str, Any]] = []
        cursor = start
        while cursor < end:
            bucket_end = min(end, cursor + bucket)
            status_counts: Counter[str] = Counter()
            reason_counts: Counter[str] = Counter()
            capabilities: Counter[str] = Counter()
            for request in requests:
                if cursor <= request.requested_at < bucket_end:
                    decision = evaluator.evaluate(request, revision)
                    status_counts[decision.status.value] += 1
                    reason_counts.update(reason.code for reason in decision.reasons)
                    capabilities[request.capability] += 1
            result.append({
                "start": format_time(cursor),
                "end": format_time(bucket_end),
                "statuses": dict(sorted(status_counts.items())),
                "reasons": dict(sorted(reason_counts.items())),
                "capabilities": dict(sorted(capabilities.items())),
                "total": sum(status_counts.values()),
            })
            cursor = bucket_end
        return result

    def denial_clusters(self, since: datetime | None = None) -> list[dict[str, Any]]:
        index = TemporalDeclarationIndex.from_store(self.store, self.parser)
        evaluator = PolicyEvaluator(index)
        revision = self.store.revision()
        clusters: dict[tuple[str, str, str], dict[str, Any]] = {}
        for payload in self.store.request_payloads(since=since):
            request = self.parser.parse_request(payload)
            decision = evaluator.evaluate(request, revision)
            if decision.status is not DecisionStatus.DENY:
                continue
            primary = decision.reasons[0].code if decision.reasons else "unknown"
            key = request.application_id, request.capability, primary
            cluster = clusters.setdefault(key, {
                "application_id": request.application_id,
                "capability": request.capability,
                "primary_reason": primary,
                "count": 0,
                "regions": Counter(),
                "device_models": Counter(),
                "request_ids": [],
                "first_seen": request.requested_at,
                "last_seen": request.requested_at,
            })
            cluster["count"] += 1
            cluster["regions"][request.region] += 1
            cluster["device_models"][request.device.model] += 1
            cluster["request_ids"].append(request.request_id)
            cluster["first_seen"] = min(cluster["first_seen"], request.requested_at)
            cluster["last_seen"] = max(cluster["last_seen"], request.requested_at)
        result = []
        for cluster in clusters.values():
            result.append({
                **{key: value for key, value in cluster.items() if key not in {"regions", "device_models", "first_seen", "last_seen"}},
                "regions": dict(sorted(cluster["regions"].items())),
                "device_models": dict(sorted(cluster["device_models"].items())),
                "first_seen": format_time(cluster["first_seen"]),
                "last_seen": format_time(cluster["last_seen"]),
            })
        result.sort(key=lambda item: (-item["count"], item["application_id"], item["capability"], item["primary_reason"]))
        return result

    def declaration_coverage(
        self,
        developer_id: str,
        application_id: str,
        agent_identity: str,
        capability: str,
        region: str,
        version: str,
        start: datetime,
        end: datetime,
    ) -> list[dict[str, Any]]:
        index = TemporalDeclarationIndex.from_store(self.store, self.parser)
        catalog = DeclarationCatalog(index.all())
        return catalog.coverage(developer_id, application_id, agent_identity, capability, region, version, start, end)

    def late_event_impact(self) -> dict[str, Any]:
        queue = self.store.queued_recomputations(10000)
        by_cause: dict[str, list[str]] = defaultdict(list)
        for item in queue:
            by_cause[item["cause_event_id"]].append(item["request_id"])
        return {
            "queued_requests": len(queue),
            "cause_count": len(by_cause),
            "causes": [
                {"event_id": event_id, "request_count": len(request_ids), "request_ids": sorted(request_ids)}
                for event_id, request_ids in sorted(by_cause.items())
            ],
        }
