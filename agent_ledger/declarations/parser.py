from __future__ import annotations

from datetime import date
from typing import Any, Mapping

from ..errors import FieldIssue, ValidationError, collect_issues
from ..models import (
    CallRequest,
    Declaration,
    DeclarationAction,
    DeviceConstraint,
    DeviceContext,
    Scope,
    VersionRange,
)
from ..util import (
    clamp_text,
    ensure_capability,
    ensure_identifier,
    ensure_region,
    ensure_version,
    parse_time,
    require_mapping,
    require_sequence,
    stable_id,
    unique_sorted,
    version_key,
)


class DeclarationParser:
    allowed_metadata = {"channel", "ticket", "operator", "source", "labels", "target_declaration_id"}

    def parse(self, payload: Mapping[str, Any]) -> Declaration:
        data = require_mapping(payload, "declaration")
        developer_id = ensure_identifier(data.get("developer_id"), "developer_id")
        application_id = self._selector(data.get("application_id"), "application_id")
        agent_identity = self._selector(data.get("agent_identity"), "agent_identity")
        action = self._action(data.get("action"))
        effective_from = parse_time(data.get("effective_from"), "effective_from")
        effective_until = self._optional_time(data.get("effective_until"), "effective_until")
        issued_at = parse_time(data.get("issued_at"), "issued_at")
        if effective_until is not None and effective_until <= effective_from:
            raise ValidationError(
                "effective_until must be later than effective_from",
                details={"effective_from": data.get("effective_from"), "effective_until": data.get("effective_until")},
            )
        priority = self._priority(data.get("priority", 0))
        inherited_from = self._optional_identifier(data.get("inherited_from"), "inherited_from")
        reason = clamp_text(data.get("reason", "developer declaration"), "reason", 512)
        nonce = clamp_text(data.get("nonce"), "nonce", 128)
        metadata = self._metadata(data.get("metadata", {}))
        scope = self._scope(data.get("scope", {}), action)
        declaration_id = data.get("declaration_id")
        if declaration_id is None:
            declaration_id = stable_id(
                "decl",
                {
                    "developer_id": developer_id,
                    "application_id": application_id,
                    "agent_identity": agent_identity,
                    "action": action.value,
                    "effective_from": effective_from.isoformat(),
                    "nonce": nonce,
                },
            )
        else:
            declaration_id = ensure_identifier(declaration_id, "declaration_id")
        return Declaration(
            declaration_id=declaration_id,
            developer_id=developer_id,
            application_id=application_id,
            agent_identity=agent_identity,
            action=action,
            scope=scope,
            effective_from=effective_from,
            effective_until=effective_until,
            priority=priority,
            inherited_from=inherited_from,
            reason=reason,
            issued_at=issued_at,
            nonce=nonce,
            metadata=metadata,
        )

    def parse_request(self, payload: Mapping[str, Any]) -> CallRequest:
        data = require_mapping(payload, "request")
        developer_id = ensure_identifier(data.get("developer_id"), "developer_id")
        application_id = ensure_identifier(data.get("application_id"), "application_id")
        application_version = ensure_version(data.get("application_version"), "application_version")
        agent_identity = ensure_identifier(data.get("agent_identity"), "agent_identity")
        capability = ensure_capability(data.get("capability"), "capability")
        region = ensure_region(data.get("region"), "region")
        requested_at = parse_time(data.get("requested_at"), "requested_at")
        device = self._device_context(data.get("device"))
        attributes = self._attributes(data.get("attributes", {}))
        request_id = data.get("request_id")
        if request_id is None:
            request_id = stable_id(
                "req",
                {
                    "developer_id": developer_id,
                    "application_id": application_id,
                    "agent_identity": agent_identity,
                    "capability": capability,
                    "device_id": device.device_id,
                    "requested_at": requested_at.isoformat(),
                },
            )
        else:
            request_id = ensure_identifier(request_id, "request_id")
        return CallRequest(
            request_id=request_id,
            developer_id=developer_id,
            application_id=application_id,
            application_version=application_version,
            agent_identity=agent_identity,
            capability=capability,
            region=region,
            requested_at=requested_at,
            device=device,
            attributes=attributes,
        )

    def _scope(self, value: Any, action: DeclarationAction) -> Scope:
        data = require_mapping(value, "scope")
        capabilities_raw = data.get("capabilities", [])
        capabilities_seq = require_sequence(capabilities_raw, "scope.capabilities")
        capabilities = unique_sorted(ensure_capability(item) for item in capabilities_seq)
        if action is not DeclarationAction.WITHDRAW and not capabilities:
            raise ValidationError("grant and deny declarations require capabilities")
        regions_raw = data.get("regions", [])
        regions_seq = require_sequence(regions_raw, "scope.regions")
        regions = unique_sorted(ensure_region(item) for item in regions_seq)
        version_range = self._version_range(data.get("version_range", {}))
        device = self._device_constraint(data.get("device", {}))
        unknown = sorted(set(data) - {"capabilities", "regions", "version_range", "device"})
        if unknown:
            raise ValidationError("unknown scope fields", details={"fields": unknown})
        return Scope(capabilities, regions, version_range, device)

    def _version_range(self, value: Any) -> VersionRange:
        data = require_mapping(value, "scope.version_range")
        minimum = data.get("minimum")
        maximum = data.get("maximum")
        if minimum is not None:
            minimum = ensure_version(minimum, "scope.version_range.minimum")
        if maximum is not None:
            maximum = ensure_version(maximum, "scope.version_range.maximum")
        if minimum is not None and maximum is not None and version_key(minimum) > version_key(maximum):
            raise ValidationError("version range minimum exceeds maximum")
        unknown = sorted(set(data) - {"minimum", "maximum"})
        if unknown:
            raise ValidationError("unknown version range fields", details={"fields": unknown})
        return VersionRange(minimum, maximum)

    def _device_constraint(self, value: Any) -> DeviceConstraint:
        data = require_mapping(value, "scope.device")
        manufacturers = self._text_set(data.get("manufacturers", []), "scope.device.manufacturers")
        models = self._text_set(data.get("models", []), "scope.device.models")
        os_families = self._text_set(data.get("os_families", []), "scope.device.os_families")
        min_patch = data.get("min_security_patch")
        if min_patch is not None:
            min_patch = self._security_patch(min_patch, "scope.device.min_security_patch")
        managed_only = data.get("managed_only", False)
        if not isinstance(managed_only, bool):
            raise ValidationError("managed_only must be boolean")
        unknown = sorted(set(data) - {"manufacturers", "models", "os_families", "min_security_patch", "managed_only"})
        if unknown:
            raise ValidationError("unknown device constraint fields", details={"fields": unknown})
        return DeviceConstraint(manufacturers, models, os_families, min_patch, managed_only)

    def _device_context(self, value: Any) -> DeviceContext:
        data = require_mapping(value, "device")
        required = {"device_id", "manufacturer", "model", "os_family", "security_patch", "managed"}
        missing = sorted(required - set(data))
        if missing:
            raise ValidationError("device context missing fields", details={"missing": missing})
        managed = data["managed"]
        if not isinstance(managed, bool):
            raise ValidationError("device.managed must be boolean")
        return DeviceContext(
            device_id=ensure_identifier(data["device_id"], "device.device_id"),
            manufacturer=clamp_text(data["manufacturer"], "device.manufacturer", 128),
            model=clamp_text(data["model"], "device.model", 128),
            os_family=clamp_text(data["os_family"], "device.os_family", 64),
            security_patch=self._security_patch(data["security_patch"], "device.security_patch"),
            managed=managed,
        )

    def _metadata(self, value: Any) -> dict[str, Any]:
        data = dict(require_mapping(value, "metadata"))
        unknown = sorted(set(data) - self.allowed_metadata)
        if unknown:
            raise ValidationError("unknown metadata fields", details={"fields": unknown})
        if "labels" in data:
            labels = self._text_set(data["labels"], "metadata.labels")
            data["labels"] = list(labels)
        for field in ("channel", "ticket", "operator", "source"):
            if field in data:
                data[field] = clamp_text(data[field], f"metadata.{field}", 256)
        if "target_declaration_id" in data:
            data["target_declaration_id"] = ensure_identifier(data["target_declaration_id"], "metadata.target_declaration_id")
        return data

    def _attributes(self, value: Any) -> dict[str, Any]:
        data = dict(require_mapping(value, "attributes"))
        if len(data) > 32:
            raise ValidationError("too many request attributes", details={"maximum": 32})
        issues: list[FieldIssue] = []
        for key, item in data.items():
            if not isinstance(key, str) or not key or len(key) > 64:
                issues.append(FieldIssue("attributes", "invalid attribute key", key))
            if isinstance(item, (dict, list, tuple, set)):
                issues.append(FieldIssue(f"attributes.{key}", "nested values are not supported", item))
            if isinstance(item, str) and len(item) > 512:
                issues.append(FieldIssue(f"attributes.{key}", "attribute value too long", item[:32]))
        collect_issues(issues)
        return data

    @staticmethod
    def _action(value: Any) -> DeclarationAction:
        try:
            return DeclarationAction(str(value))
        except ValueError as exc:
            raise ValidationError("invalid declaration action", details={"value": value}) from exc

    @staticmethod
    def _priority(value: Any) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or value < -1000 or value > 1000:
            raise ValidationError("priority must be an integer between -1000 and 1000")
        return value

    @staticmethod
    def _optional_time(value: Any, field: str):
        return None if value is None else parse_time(value, field)

    @staticmethod
    def _optional_identifier(value: Any, field: str) -> str | None:
        return None if value is None else ensure_identifier(value, field)

    @staticmethod
    def _text_set(value: Any, field: str) -> tuple[str, ...]:
        sequence = require_sequence(value, field)
        texts = [clamp_text(item, field, 128) for item in sequence]
        return unique_sorted(texts)

    @staticmethod
    def _security_patch(value: Any, field: str) -> str:
        text = clamp_text(value, field, 10)
        try:
            date.fromisoformat(text)
        except ValueError as exc:
            raise ValidationError("security patch must use YYYY-MM-DD", details={"field": field}) from exc
        return text

    @staticmethod
    def _selector(value: Any, field: str) -> str:
        if value == "*":
            return "*"
        return ensure_identifier(value, field)
