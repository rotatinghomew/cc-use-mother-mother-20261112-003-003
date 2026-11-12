from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Any, Callable

from ..models import CallRequest, Declaration
from ..util import in_version_range


@dataclass(frozen=True)
class MatchFailure:
    code: str
    message: str
    field: str
    expected: Any
    actual: Any

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "field": self.field,
            "expected": self.expected,
            "actual": self.actual,
        }


@dataclass(frozen=True)
class MatchResult:
    matched: bool
    failures: tuple[MatchFailure, ...] = ()
    dimensions: dict[str, bool] = field(default_factory=dict)

    @property
    def first_failure(self) -> MatchFailure | None:
        return self.failures[0] if self.failures else None

    def as_dict(self) -> dict[str, Any]:
        return {
            "matched": self.matched,
            "failures": [item.as_dict() for item in self.failures],
            "dimensions": self.dimensions,
        }


class ConstraintMatcher:
    def __init__(self) -> None:
        self._rules: tuple[tuple[str, Callable[[Declaration, CallRequest], MatchFailure | None]], ...] = (
            ("developer", self._developer),
            ("application", self._application),
            ("agent", self._agent),
            ("capability", self._capability),
            ("region", self._region),
            ("version", self._version),
            ("manufacturer", self._manufacturer),
            ("model", self._model),
            ("os_family", self._os_family),
            ("security_patch", self._security_patch),
            ("managed", self._managed),
        )

    def match(self, declaration: Declaration, request: CallRequest) -> MatchResult:
        failures: list[MatchFailure] = []
        dimensions: dict[str, bool] = {}
        for name, rule in self._rules:
            failure = rule(declaration, request)
            dimensions[name] = failure is None
            if failure is not None:
                failures.append(failure)
        return MatchResult(not failures, tuple(failures), dimensions)

    def describe(self, declaration: Declaration, request: CallRequest) -> list[str]:
        result = self.match(declaration, request)
        if result.matched:
            return ["all declaration constraints matched the call request"]
        return [failure.message for failure in result.failures]

    @staticmethod
    def _developer(declaration: Declaration, request: CallRequest) -> MatchFailure | None:
        if declaration.developer_id == request.developer_id:
            return None
        return MatchFailure("developer_mismatch", "developer identity differs from declaration owner", "developer_id", declaration.developer_id, request.developer_id)

    @staticmethod
    def _application(declaration: Declaration, request: CallRequest) -> MatchFailure | None:
        if declaration.application_id in {"*", request.application_id}:
            return None
        return MatchFailure("application_mismatch", "application is outside the declaration selector", "application_id", declaration.application_id, request.application_id)

    @staticmethod
    def _agent(declaration: Declaration, request: CallRequest) -> MatchFailure | None:
        if declaration.agent_identity in {"*", request.agent_identity}:
            return None
        return MatchFailure("agent_mismatch", "agent identity is outside the declaration selector", "agent_identity", declaration.agent_identity, request.agent_identity)

    @staticmethod
    def _capability(declaration: Declaration, request: CallRequest) -> MatchFailure | None:
        capabilities = declaration.scope.capabilities
        if not capabilities or request.capability in capabilities or "*" in capabilities:
            return None
        return MatchFailure("capability_out_of_scope", "requested capability was not electronically declared", "capability", list(capabilities), request.capability)

    @staticmethod
    def _region(declaration: Declaration, request: CallRequest) -> MatchFailure | None:
        regions = declaration.scope.regions
        if not regions or request.region in regions:
            return None
        return MatchFailure("region_out_of_scope", "request region is outside the declared region scope", "region", list(regions), request.region)

    @staticmethod
    def _version(declaration: Declaration, request: CallRequest) -> MatchFailure | None:
        version_range = declaration.scope.version_range
        if in_version_range(request.application_version, version_range.minimum, version_range.maximum):
            return None
        return MatchFailure(
            "version_out_of_scope",
            "application version is outside the declared version range",
            "application_version",
            version_range.as_dict(),
            request.application_version,
        )

    @staticmethod
    def _manufacturer(declaration: Declaration, request: CallRequest) -> MatchFailure | None:
        values = declaration.scope.device.manufacturers
        if not values or request.device.manufacturer in values:
            return None
        return MatchFailure("manufacturer_out_of_scope", "device manufacturer is outside the declared constraint", "device.manufacturer", list(values), request.device.manufacturer)

    @staticmethod
    def _model(declaration: Declaration, request: CallRequest) -> MatchFailure | None:
        values = declaration.scope.device.models
        if not values or request.device.model in values:
            return None
        return MatchFailure("model_out_of_scope", "device model is outside the declared constraint", "device.model", list(values), request.device.model)

    @staticmethod
    def _os_family(declaration: Declaration, request: CallRequest) -> MatchFailure | None:
        values = declaration.scope.device.os_families
        if not values or request.device.os_family in values:
            return None
        return MatchFailure("os_out_of_scope", "device operating system is outside the declared constraint", "device.os_family", list(values), request.device.os_family)

    @staticmethod
    def _security_patch(declaration: Declaration, request: CallRequest) -> MatchFailure | None:
        minimum = declaration.scope.device.min_security_patch
        if minimum is None or date.fromisoformat(request.device.security_patch) >= date.fromisoformat(minimum):
            return None
        return MatchFailure("security_patch_too_old", "device security patch is older than the declared minimum", "device.security_patch", minimum, request.device.security_patch)

    @staticmethod
    def _managed(declaration: Declaration, request: CallRequest) -> MatchFailure | None:
        if not declaration.scope.device.managed_only or request.device.managed:
            return None
        return MatchFailure("managed_device_required", "declaration only authorizes managed devices", "device.managed", True, request.device.managed)
