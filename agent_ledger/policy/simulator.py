from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Iterable, Mapping

from ..declarations.catalog import DeclarationCatalog
from ..declarations.parser import DeclarationParser
from ..errors import ValidationError
from ..models import CallRequest, Decision, DecisionStatus, Declaration
from ..temporal.index import TemporalDeclarationIndex
from ..temporal.store import LedgerStore
from ..util import format_time, parse_time
from .evaluator import PolicyEvaluator


@dataclass(frozen=True)
class DecisionChange:
    request_id: str
    before_status: str
    after_status: str
    before_reasons: tuple[str, ...]
    after_reasons: tuple[str, ...]
    before_declarations: tuple[str, ...]
    after_declarations: tuple[str, ...]

    @property
    def status_changed(self) -> bool:
        return self.before_status != self.after_status

    @property
    def reasons_changed(self) -> bool:
        return self.before_reasons != self.after_reasons

    def as_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "before_status": self.before_status,
            "after_status": self.after_status,
            "before_reasons": list(self.before_reasons),
            "after_reasons": list(self.after_reasons),
            "before_declarations": list(self.before_declarations),
            "after_declarations": list(self.after_declarations),
            "status_changed": self.status_changed,
            "reasons_changed": self.reasons_changed,
        }


@dataclass(frozen=True)
class SimulationResult:
    evaluated: int
    unchanged: int
    changes: tuple[DecisionChange, ...]
    before_counts: dict[str, int]
    after_counts: dict[str, int]
    proposed_ids: tuple[str, ...]
    removed_ids: tuple[str, ...]
    warnings: tuple[dict[str, Any], ...]

    @property
    def status_changes(self) -> int:
        return sum(item.status_changed for item in self.changes)

    @property
    def explanation_changes(self) -> int:
        return sum(item.reasons_changed and not item.status_changed for item in self.changes)

    def as_dict(self) -> dict[str, Any]:
        return {
            "summary": {
                "evaluated": self.evaluated,
                "unchanged": self.unchanged,
                "changed": len(self.changes),
                "status_changes": self.status_changes,
                "explanation_changes": self.explanation_changes,
            },
            "before_counts": self.before_counts,
            "after_counts": self.after_counts,
            "proposed_ids": list(self.proposed_ids),
            "removed_ids": list(self.removed_ids),
            "warnings": list(self.warnings),
            "changes": [item.as_dict() for item in self.changes],
        }


class PolicySimulator:
    def __init__(self, store: LedgerStore, parser: DeclarationParser | None = None) -> None:
        self.store = store
        self.parser = parser or DeclarationParser()

    def simulate(
        self,
        proposals: Iterable[Declaration | Mapping[str, Any]] = (),
        *,
        remove_ids: Iterable[str] = (),
        requests: Iterable[CallRequest | Mapping[str, Any]] | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> SimulationResult:
        baseline_declarations = [self.parser.parse(payload) for payload in self.store.declaration_payloads()]
        parsed_proposals = [item if isinstance(item, Declaration) else self.parser.parse(item) for item in proposals]
        removed = tuple(sorted(set(remove_ids)))
        baseline_ids = {item.declaration_id for item in baseline_declarations}
        unknown_removed = sorted(set(removed) - baseline_ids)
        if unknown_removed:
            raise ValidationError("simulation requested removal of unknown declarations", details={"declaration_ids": unknown_removed})
        proposal_ids = [item.declaration_id for item in parsed_proposals]
        if len(proposal_ids) != len(set(proposal_ids)):
            raise ValidationError("simulation contains duplicate proposed declaration ids")
        effective = [item for item in baseline_declarations if item.declaration_id not in removed]
        effective_by_id = {item.declaration_id: item for item in effective}
        for proposal in parsed_proposals:
            effective_by_id[proposal.declaration_id] = proposal
        effective = list(effective_by_id.values())
        baseline_index = TemporalDeclarationIndex(baseline_declarations)
        simulated_index = TemporalDeclarationIndex(effective)
        baseline_evaluator = PolicyEvaluator(baseline_index)
        simulated_evaluator = PolicyEvaluator(simulated_index)
        actual_requests = self._requests(requests, since, until)
        revision = self.store.revision()
        changes: list[DecisionChange] = []
        before_counts: Counter[str] = Counter()
        after_counts: Counter[str] = Counter()
        unchanged = 0
        for request in actual_requests:
            before = baseline_evaluator.evaluate(request, revision)
            after = simulated_evaluator.evaluate(request, revision)
            before_counts[before.status.value] += 1
            after_counts[after.status.value] += 1
            change = self._change(request.request_id, before, after)
            if change is None:
                unchanged += 1
            else:
                changes.append(change)
        warnings = self._warnings(baseline_declarations, effective, parsed_proposals, removed, changes)
        changes.sort(key=lambda item: item.request_id)
        return SimulationResult(
            evaluated=len(actual_requests),
            unchanged=unchanged,
            changes=tuple(changes),
            before_counts=dict(sorted(before_counts.items())),
            after_counts=dict(sorted(after_counts.items())),
            proposed_ids=tuple(sorted(proposal_ids)),
            removed_ids=removed,
            warnings=tuple(warnings),
        )

    def blast_radius(
        self,
        proposals: Iterable[Declaration | Mapping[str, Any]] = (),
        *,
        remove_ids: Iterable[str] = (),
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> dict[str, Any]:
        result = self.simulate(proposals, remove_ids=remove_ids, since=since, until=until)
        applications: dict[str, Counter[str]] = defaultdict(Counter)
        capabilities: dict[str, Counter[str]] = defaultdict(Counter)
        regions: dict[str, Counter[str]] = defaultdict(Counter)
        request_lookup = {payload["request_id"]: payload for payload in self.store.request_payloads(since=since)}
        for change in result.changes:
            payload = request_lookup.get(change.request_id)
            if payload is None:
                continue
            transition = f"{change.before_status}->{change.after_status}"
            applications[payload["application_id"]][transition] += 1
            capabilities[payload["capability"]][transition] += 1
            regions[payload["region"]][transition] += 1
        return {
            "simulation": result.as_dict(),
            "applications": self._counter_map(applications),
            "capabilities": self._counter_map(capabilities),
            "regions": self._counter_map(regions),
        }

    def compare_proposals(
        self,
        alternatives: Mapping[str, Iterable[Declaration | Mapping[str, Any]]],
        *,
        remove_ids: Iterable[str] = (),
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> dict[str, Any]:
        if not alternatives:
            raise ValidationError("at least one policy alternative is required")
        results: dict[str, SimulationResult] = {}
        for name, proposals in alternatives.items():
            if not isinstance(name, str) or not name.strip():
                raise ValidationError("alternative names must be non-empty strings")
            results[name] = self.simulate(proposals, remove_ids=remove_ids, since=since, until=until)
        ranking = sorted(
            results,
            key=lambda name: (
                results[name].after_counts.get(DecisionStatus.DENY.value, 0),
                results[name].status_changes,
                len(results[name].warnings),
                name,
            ),
        )
        return {
            "ranking": ranking,
            "alternatives": {name: results[name].as_dict() for name in sorted(results)},
            "ranking_basis": ["fewer_denials", "fewer_status_changes", "fewer_warnings", "name"],
        }

    def uncovered_requests(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[dict[str, Any]]:
        declarations = [self.parser.parse(payload) for payload in self.store.declaration_payloads()]
        evaluator = PolicyEvaluator(TemporalDeclarationIndex(declarations))
        revision = self.store.revision()
        rows: list[dict[str, Any]] = []
        for request in self._requests(None, since, until):
            decision = evaluator.evaluate(request, revision)
            if decision.status is DecisionStatus.ALLOW:
                continue
            reason_codes = [item.code for item in decision.reasons]
            if "explicit_denial" in reason_codes:
                continue
            rows.append({
                "request_id": request.request_id,
                "requested_at": format_time(request.requested_at),
                "developer_id": request.developer_id,
                "application_id": request.application_id,
                "agent_identity": request.agent_identity,
                "capability": request.capability,
                "region": request.region,
                "application_version": request.application_version,
                "reason_codes": reason_codes,
            })
        rows.sort(key=lambda item: (item["application_id"], item["capability"], item["requested_at"], item["request_id"]))
        return rows

    def suggest_scopes(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        minimum_occurrences: int = 1,
    ) -> list[dict[str, Any]]:
        if minimum_occurrences <= 0:
            raise ValidationError("minimum_occurrences must be positive")
        groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
        for item in self.uncovered_requests(since=since, until=until):
            key = item["developer_id"], item["application_id"], item["agent_identity"], item["capability"]
            groups[key].append(item)
        suggestions: list[dict[str, Any]] = []
        for key, rows in groups.items():
            if len(rows) < minimum_occurrences:
                continue
            versions = sorted({row["application_version"] for row in rows})
            regions = sorted({row["region"] for row in rows})
            reasons = Counter(code for row in rows for code in row["reason_codes"])
            suggestions.append({
                "developer_id": key[0],
                "application_id": key[1],
                "agent_identity": key[2],
                "capability": key[3],
                "observed_requests": len(rows),
                "regions": regions,
                "observed_versions": versions,
                "first_seen": min(row["requested_at"] for row in rows),
                "last_seen": max(row["requested_at"] for row in rows),
                "reason_counts": dict(sorted(reasons.items())),
                "recommendation": "review and explicitly grant or deny; do not auto-authorize from observation",
            })
        suggestions.sort(key=lambda item: (-item["observed_requests"], item["application_id"], item["capability"]))
        return suggestions

    def change_windows(
        self,
        proposals: Iterable[Declaration | Mapping[str, Any]] = (),
        *,
        remove_ids: Iterable[str] = (),
        since: datetime | None = None,
        until: datetime | None = None,
        bucket_seconds: int = 86400,
    ) -> list[dict[str, Any]]:
        if bucket_seconds <= 0:
            raise ValidationError("bucket_seconds must be positive")
        requests = self._requests(None, since, until)
        result = self.simulate(proposals, remove_ids=remove_ids, requests=requests, since=since, until=until)
        request_times = {item.request_id: item.requested_at for item in requests}
        if not request_times:
            return []
        origin = since or min(request_times.values())
        buckets: dict[int, dict[str, Any]] = {}
        for change in result.changes:
            requested_at = request_times[change.request_id]
            index = int((requested_at - origin).total_seconds() // bucket_seconds)
            start = origin + timedelta(seconds=index * bucket_seconds)
            end = start + timedelta(seconds=bucket_seconds)
            bucket = buckets.setdefault(index, {
                "start": format_time(start),
                "end": format_time(end),
                "changed": 0,
                "status_changes": 0,
                "explanation_changes": 0,
                "transitions": Counter(),
                "request_ids": [],
            })
            bucket["changed"] += 1
            bucket["status_changes"] += int(change.status_changed)
            bucket["explanation_changes"] += int(change.reasons_changed and not change.status_changed)
            bucket["transitions"][f"{change.before_status}->{change.after_status}"] += 1
            bucket["request_ids"].append(change.request_id)
        rows: list[dict[str, Any]] = []
        for index in sorted(buckets):
            bucket = buckets[index]
            rows.append({
                **{key: value for key, value in bucket.items() if key != "transitions"},
                "transitions": dict(sorted(bucket["transitions"].items())),
                "request_ids": sorted(bucket["request_ids"]),
            })
        return rows

    def validate_proposals(
        self,
        proposals: Iterable[Declaration | Mapping[str, Any]],
        *,
        remove_ids: Iterable[str] = (),
    ) -> dict[str, Any]:
        baseline = [self.parser.parse(payload) for payload in self.store.declaration_payloads()]
        removed = set(remove_ids)
        effective = [item for item in baseline if item.declaration_id not in removed]
        parsed = [item if isinstance(item, Declaration) else self.parser.parse(item) for item in proposals]
        by_id = {item.declaration_id: item for item in effective}
        for proposal in parsed:
            by_id[proposal.declaration_id] = proposal
        catalog = DeclarationCatalog(by_id.values())
        conflicts = catalog.conflicts()
        ambiguous = catalog.ambiguous_conflicts()
        graph = catalog.inheritance_graph()
        errors: list[dict[str, Any]] = []
        warnings: list[dict[str, Any]] = []
        for declaration_id, parent in graph["missing_parents"].items():
            errors.append({
                "code": "missing_parent",
                "declaration_id": declaration_id,
                "parent": parent,
                "message": "proposed declaration inherits from an unavailable parent",
            })
        for overlap in ambiguous:
            warnings.append({
                "code": "ambiguous_conflict",
                "left_id": overlap.left_id,
                "right_id": overlap.right_id,
                "message": "grant and deny overlap at equal priority and specificity; deny will win",
            })
        return {
            "valid": not errors,
            "errors": errors,
            "warnings": warnings,
            "inventory": catalog.inventory(),
            "conflicts": [item.as_dict() for item in conflicts],
            "inheritance": graph,
        }

    def _requests(
        self,
        requests: Iterable[CallRequest | Mapping[str, Any]] | None,
        since: datetime | None,
        until: datetime | None,
    ) -> list[CallRequest]:
        if since is not None and until is not None and since >= until:
            raise ValidationError("simulation since must be earlier than until")
        values: Iterable[CallRequest | Mapping[str, Any]]
        if requests is None:
            values = self.store.request_payloads(since=since)
        else:
            values = requests
        result: list[CallRequest] = []
        for value in values:
            request = value if isinstance(value, CallRequest) else self.parser.parse_request(value)
            if since is not None and request.requested_at < since:
                continue
            if until is not None and request.requested_at >= until:
                continue
            result.append(request)
        result.sort(key=lambda item: (item.requested_at, item.request_id))
        return result

    @staticmethod
    def _change(request_id: str, before: Decision, after: Decision) -> DecisionChange | None:
        before_reasons = tuple(item.code for item in before.reasons)
        after_reasons = tuple(item.code for item in after.reasons)
        if (
            before.status is after.status
            and before_reasons == after_reasons
            and before.matched_declarations == after.matched_declarations
        ):
            return None
        return DecisionChange(
            request_id=request_id,
            before_status=before.status.value,
            after_status=after.status.value,
            before_reasons=before_reasons,
            after_reasons=after_reasons,
            before_declarations=before.matched_declarations,
            after_declarations=after.matched_declarations,
        )

    def _warnings(
        self,
        baseline: list[Declaration],
        effective: list[Declaration],
        proposals: list[Declaration],
        removed: tuple[str, ...],
        changes: list[DecisionChange],
    ) -> list[dict[str, Any]]:
        warnings: list[dict[str, Any]] = []
        catalog = DeclarationCatalog(effective)
        for conflict in catalog.ambiguous_conflicts():
            warnings.append({
                "code": "ambiguous_conflict",
                "message": "equal-rank grant and deny overlap; deny will win",
                "left_id": conflict.left_id,
                "right_id": conflict.right_id,
                "start": format_time(conflict.start),
                "end": format_time(conflict.end),
            })
        graph = catalog.inheritance_graph()
        for declaration_id, parent in graph["missing_parents"].items():
            warnings.append({
                "code": "missing_parent",
                "message": "declaration inheritance parent is missing after the proposed change",
                "declaration_id": declaration_id,
                "parent": parent,
            })
        allow_to_deny = [item.request_id for item in changes if item.before_status == "allow" and item.after_status == "deny"]
        if allow_to_deny:
            warnings.append({
                "code": "allow_to_deny",
                "message": "proposed policy would newly deny previously authorized requests",
                "count": len(allow_to_deny),
                "request_ids": allow_to_deny[:100],
            })
        deny_to_allow = [item.request_id for item in changes if item.before_status == "deny" and item.after_status == "allow"]
        if deny_to_allow:
            warnings.append({
                "code": "deny_to_allow",
                "message": "proposed policy would authorize previously denied requests",
                "count": len(deny_to_allow),
                "request_ids": deny_to_allow[:100],
            })
        baseline_ids = {item.declaration_id for item in baseline}
        replaced = sorted(item.declaration_id for item in proposals if item.declaration_id in baseline_ids and item.declaration_id not in removed)
        if replaced:
            warnings.append({
                "code": "in_place_replacement",
                "message": "simulation replaces existing declaration content by id; production ingest would require a new immutable id",
                "declaration_ids": replaced,
            })
        warnings.sort(key=lambda item: (item["code"], str(item.get("declaration_id", ""))))
        return warnings

    @staticmethod
    def _counter_map(value: dict[str, Counter[str]]) -> dict[str, dict[str, int]]:
        return {key: dict(sorted(counter.items())) for key, counter in sorted(value.items())}
