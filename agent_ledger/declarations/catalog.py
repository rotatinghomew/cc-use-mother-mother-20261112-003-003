from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable

from ..models import Declaration, DeclarationAction
from ..temporal.index import TemporalDeclarationIndex
from ..util import format_time, in_version_range


@dataclass(frozen=True)
class Overlap:
    left_id: str
    right_id: str
    start: datetime
    end: datetime | None
    capability_overlap: tuple[str, ...]
    region_overlap: tuple[str, ...]
    conflicting_action: bool
    same_rank: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "left_id": self.left_id,
            "right_id": self.right_id,
            "start": format_time(self.start),
            "end": format_time(self.end),
            "capability_overlap": list(self.capability_overlap),
            "region_overlap": list(self.region_overlap),
            "conflicting_action": self.conflicting_action,
            "same_rank": self.same_rank,
        }


class DeclarationCatalog:
    def __init__(self, declarations: Iterable[Declaration]) -> None:
        self.declarations = tuple(sorted(declarations, key=lambda item: (item.effective_from, item.declaration_id)))
        self.index = TemporalDeclarationIndex(self.declarations)

    def find_overlaps(self) -> tuple[Overlap, ...]:
        grouped: dict[str, list[Declaration]] = defaultdict(list)
        for declaration in self.declarations:
            grouped[declaration.developer_id].append(declaration)
        overlaps: list[Overlap] = []
        for declarations in grouped.values():
            for left_index, left in enumerate(declarations):
                if left.action is DeclarationAction.WITHDRAW:
                    continue
                for right in declarations[left_index + 1:]:
                    if right.action is DeclarationAction.WITHDRAW:
                        continue
                    overlap = self._overlap(left, right)
                    if overlap is not None:
                        overlaps.append(overlap)
        overlaps.sort(key=lambda item: (item.start, item.left_id, item.right_id))
        return tuple(overlaps)

    def conflicts(self) -> tuple[Overlap, ...]:
        return tuple(item for item in self.find_overlaps() if item.conflicting_action)

    def ambiguous_conflicts(self) -> tuple[Overlap, ...]:
        return tuple(item for item in self.find_overlaps() if item.conflicting_action and item.same_rank)

    def coverage(
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
        boundaries = {start, end}
        for declaration in self.declarations:
            if declaration.developer_id != developer_id:
                continue
            if declaration.application_id not in {"*", application_id}:
                continue
            if declaration.agent_identity not in {"*", agent_identity}:
                continue
            if declaration.effective_from < end and (declaration.effective_until is None or declaration.effective_until > start):
                boundaries.add(max(start, declaration.effective_from))
                if declaration.effective_until is not None:
                    boundaries.add(min(end, declaration.effective_until))
        ordered = sorted(boundaries)
        result: list[dict[str, Any]] = []
        for left, right in zip(ordered, ordered[1:]):
            active = self.index.active(developer_id, application_id, agent_identity, left)
            relevant = [
                declaration for declaration in active
                if self._capability_matches(declaration, capability)
                and self._region_matches(declaration, region)
                and in_version_range(version, declaration.scope.version_range.minimum, declaration.scope.version_range.maximum)
            ]
            grants = [item for item in relevant if item.action is DeclarationAction.GRANT]
            denies = [item for item in relevant if item.action is DeclarationAction.DENY]
            result.append({
                "start": format_time(left),
                "end": format_time(right),
                "covered": bool(grants),
                "denied": bool(denies),
                "grant_ids": [item.declaration_id for item in grants],
                "deny_ids": [item.declaration_id for item in denies],
            })
        return self._merge_adjacent(result)

    def inheritance_graph(self) -> dict[str, Any]:
        roots: list[str] = []
        children: dict[str, list[str]] = defaultdict(list)
        missing: dict[str, str] = {}
        known = {item.declaration_id for item in self.declarations}
        for declaration in self.declarations:
            if declaration.inherited_from is None:
                roots.append(declaration.declaration_id)
            elif declaration.inherited_from not in known:
                missing[declaration.declaration_id] = declaration.inherited_from
            else:
                children[declaration.inherited_from].append(declaration.declaration_id)
        for values in children.values():
            values.sort()
        return {
            "roots": sorted(roots),
            "children": dict(sorted(children.items())),
            "missing_parents": dict(sorted(missing.items())),
            "max_depth": self._max_depth(children, roots),
        }

    def inventory(self) -> dict[str, Any]:
        action_counts: dict[str, int] = defaultdict(int)
        capability_counts: dict[str, int] = defaultdict(int)
        region_counts: dict[str, int] = defaultdict(int)
        developer_counts: dict[str, int] = defaultdict(int)
        for declaration in self.declarations:
            action_counts[declaration.action.value] += 1
            developer_counts[declaration.developer_id] += 1
            for capability in declaration.scope.capabilities:
                capability_counts[capability] += 1
            for region in declaration.scope.regions or ("*",):
                region_counts[region] += 1
        return {
            "total": len(self.declarations),
            "actions": dict(sorted(action_counts.items())),
            "developers": dict(sorted(developer_counts.items())),
            "capabilities": dict(sorted(capability_counts.items())),
            "regions": dict(sorted(region_counts.items())),
            "overlap_count": len(self.find_overlaps()),
            "conflict_count": len(self.conflicts()),
            "ambiguous_conflict_count": len(self.ambiguous_conflicts()),
        }

    def _overlap(self, left: Declaration, right: Declaration) -> Overlap | None:
        if not self._selectors_overlap(left.application_id, right.application_id):
            return None
        if not self._selectors_overlap(left.agent_identity, right.agent_identity):
            return None
        start = max(left.effective_from, right.effective_from)
        end = self._minimum_end(left.effective_until, right.effective_until)
        if end is not None and start >= end:
            return None
        capabilities = self._set_overlap(left.scope.capabilities, right.scope.capabilities, wildcard=True)
        if not capabilities:
            return None
        regions = self._set_overlap(left.scope.regions, right.scope.regions, wildcard=True)
        if not regions:
            return None
        if not self._version_ranges_overlap(left, right):
            return None
        return Overlap(
            left.declaration_id, right.declaration_id, start, end, capabilities, regions,
            left.action is not right.action,
            left.priority == right.priority and self.index.specificity(left) == self.index.specificity(right),
        )

    @staticmethod
    def _selectors_overlap(left: str, right: str) -> bool:
        return left == "*" or right == "*" or left == right

    @staticmethod
    def _minimum_end(left: datetime | None, right: datetime | None) -> datetime | None:
        if left is None:
            return right
        if right is None:
            return left
        return min(left, right)

    @staticmethod
    def _set_overlap(left: tuple[str, ...], right: tuple[str, ...], *, wildcard: bool) -> tuple[str, ...]:
        if not left and wildcard:
            return right or ("*",)
        if not right and wildcard:
            return left or ("*",)
        return tuple(sorted(set(left) & set(right)))

    @staticmethod
    def _version_ranges_overlap(left: Declaration, right: Declaration) -> bool:
        left_range = left.scope.version_range
        right_range = right.scope.version_range
        if left_range.maximum is not None and right_range.minimum is not None:
            if not in_version_range(left_range.maximum, right_range.minimum, None):
                return False
        if right_range.maximum is not None and left_range.minimum is not None:
            if not in_version_range(right_range.maximum, left_range.minimum, None):
                return False
        return True

    @staticmethod
    def _capability_matches(declaration: Declaration, capability: str) -> bool:
        return capability in declaration.scope.capabilities

    @staticmethod
    def _region_matches(declaration: Declaration, region: str) -> bool:
        return not declaration.scope.regions or region in declaration.scope.regions

    @staticmethod
    def _merge_adjacent(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for row in rows:
            if result and all(result[-1][key] == row[key] for key in ("covered", "denied", "grant_ids", "deny_ids")):
                result[-1]["end"] = row["end"]
            else:
                result.append(dict(row))
        return result

    @staticmethod
    def _max_depth(children: dict[str, list[str]], roots: list[str]) -> int:
        maximum = 0
        frontier = [(root, 1) for root in roots]
        while frontier:
            node, depth = frontier.pop()
            maximum = max(maximum, depth)
            frontier.extend((child, depth + 1) for child in children.get(node, []))
        return maximum
