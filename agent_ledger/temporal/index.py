from __future__ import annotations

from bisect import bisect_right
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

from ..declarations.parser import DeclarationParser
from ..errors import PolicyError
from ..models import Declaration, DeclarationAction
from .store import LedgerStore


@dataclass(frozen=True)
class IntervalEntry:
    start: datetime
    end: datetime | None
    declaration: Declaration

    def contains(self, point: datetime) -> bool:
        return self.start <= point and (self.end is None or point < self.end)


class TemporalDeclarationIndex:
    def __init__(self, declarations: Iterable[Declaration] = ()) -> None:
        self._entries: dict[tuple[str, str, str], list[IntervalEntry]] = defaultdict(list)
        self._starts: dict[tuple[str, str, str], list[datetime]] = defaultdict(list)
        self._by_id: dict[str, Declaration] = {}
        self.rebuild(declarations)

    @classmethod
    def from_store(cls, store: LedgerStore, parser: DeclarationParser | None = None) -> "TemporalDeclarationIndex":
        actual_parser = parser or DeclarationParser()
        return cls(actual_parser.parse(payload) for payload in store.declaration_payloads())

    def rebuild(self, declarations: Iterable[Declaration]) -> None:
        self._entries.clear()
        self._starts.clear()
        self._by_id.clear()
        for declaration in declarations:
            self.add(declaration, resort=False)
        for key in self._entries:
            self._sort(key)
        self._validate_inheritance()

    def add(self, declaration: Declaration, *, resort: bool = True) -> None:
        existing = self._by_id.get(declaration.declaration_id)
        if existing is not None and existing != declaration:
            raise PolicyError("declaration id collision in temporal index", details={"declaration_id": declaration.declaration_id})
        if existing is not None:
            return
        key = self.key_for(declaration)
        self._entries[key].append(IntervalEntry(declaration.effective_from, declaration.effective_until, declaration))
        self._by_id[declaration.declaration_id] = declaration
        if resort:
            self._sort(key)
            self._validate_declaration_inheritance(declaration)

    def remove(self, declaration_id: str) -> bool:
        declaration = self._by_id.pop(declaration_id, None)
        if declaration is None:
            return False
        key = self.key_for(declaration)
        self._entries[key] = [entry for entry in self._entries[key] if entry.declaration.declaration_id != declaration_id]
        self._sort(key)
        return True

    def active(self, developer_id: str, application_id: str, agent_identity: str, point: datetime) -> tuple[Declaration, ...]:
        keys = [
            (developer_id, application_id, agent_identity),
            (developer_id, "*", agent_identity),
            (developer_id, application_id, "*"),
            (developer_id, "*", "*"),
        ]
        matches: list[Declaration] = []
        seen: set[str] = set()
        for key in keys:
            entries = self._entries.get(key, [])
            starts = self._starts.get(key, [])
            limit = bisect_right(starts, point)
            for entry in entries[:limit]:
                declaration = entry.declaration
                if declaration.declaration_id in seen or not entry.contains(point):
                    continue
                if self._is_withdrawn(declaration, point, entries[:limit]):
                    continue
                matches.append(declaration)
                seen.add(declaration.declaration_id)
        matches.sort(key=self.rank, reverse=True)
        return tuple(matches)

    def chain(self, declaration: Declaration) -> tuple[Declaration, ...]:
        chain = [declaration]
        seen = {declaration.declaration_id}
        current = declaration
        while current.inherited_from is not None:
            parent = self._by_id.get(current.inherited_from)
            if parent is None:
                raise PolicyError("inherited declaration is missing", details={"declaration_id": current.declaration_id, "parent": current.inherited_from})
            if parent.declaration_id in seen:
                raise PolicyError("declaration inheritance contains a cycle", details={"declaration_id": current.declaration_id})
            chain.append(parent)
            seen.add(parent.declaration_id)
            current = parent
        return tuple(chain)

    def descendants(self, declaration_id: str) -> tuple[Declaration, ...]:
        result: list[Declaration] = []
        frontier = [declaration_id]
        while frontier:
            parent = frontier.pop()
            children = [item for item in self._by_id.values() if item.inherited_from == parent]
            result.extend(children)
            frontier.extend(item.declaration_id for item in children)
        result.sort(key=lambda item: (item.effective_from, item.declaration_id))
        return tuple(result)

    def all(self) -> tuple[Declaration, ...]:
        return tuple(sorted(self._by_id.values(), key=lambda item: (item.effective_from, item.declaration_id)))

    def timeline(self, developer_id: str, application_id: str, agent_identity: str) -> tuple[IntervalEntry, ...]:
        return tuple(self._entries.get((developer_id, application_id, agent_identity), ()))

    def get(self, declaration_id: str) -> Declaration | None:
        return self._by_id.get(declaration_id)

    @staticmethod
    def key_for(declaration: Declaration) -> tuple[str, str, str]:
        return declaration.developer_id, declaration.application_id, declaration.agent_identity

    @staticmethod
    def specificity(declaration: Declaration) -> int:
        score = 0
        if declaration.application_id != "*":
            score += 2
        if declaration.agent_identity != "*":
            score += 2
        if declaration.scope.regions:
            score += 1
        if declaration.scope.device.manufacturers or declaration.scope.device.models or declaration.scope.device.os_families:
            score += 1
        if declaration.scope.version_range.minimum or declaration.scope.version_range.maximum:
            score += 1
        return score

    @classmethod
    def rank(cls, declaration: Declaration) -> tuple[int, int, int, datetime, datetime, str]:
        deny_weight = 1 if declaration.action is DeclarationAction.DENY else 0
        inherited_weight = 0 if declaration.inherited_from is None else 1
        return (
            declaration.priority,
            cls.specificity(declaration),
            deny_weight,
            declaration.effective_from,
            declaration.issued_at,
            declaration.declaration_id,
        )

    def _sort(self, key: tuple[str, str, str]) -> None:
        self._entries[key].sort(key=lambda item: (item.start, item.declaration.priority, item.declaration.declaration_id))
        self._starts[key] = [item.start for item in self._entries[key]]

    def _is_withdrawn(self, declaration: Declaration, point: datetime, candidates: list[IntervalEntry]) -> bool:
        for entry in candidates:
            withdrawal = entry.declaration
            if withdrawal.action is not DeclarationAction.WITHDRAW or not entry.contains(point):
                continue
            target = withdrawal.metadata.get("target_declaration_id") or withdrawal.inherited_from
            if target == declaration.declaration_id:
                return True
            if target is None and withdrawal.scope.capabilities:
                if set(declaration.scope.capabilities) & set(withdrawal.scope.capabilities):
                    return True
        return False

    def _validate_inheritance(self) -> None:
        for declaration in self._by_id.values():
            self._validate_declaration_inheritance(declaration)

    def _validate_declaration_inheritance(self, declaration: Declaration) -> None:
        if declaration.inherited_from is None:
            return
        parent = self._by_id.get(declaration.inherited_from)
        if parent is None:
            return
        if parent.developer_id != declaration.developer_id:
            raise PolicyError("declaration cannot inherit across developers", details={"declaration_id": declaration.declaration_id})
        self.chain(declaration)
