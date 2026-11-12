from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from agent_ledger.declarations.parser import DeclarationParser
from agent_ledger.ingest.processor import LedgerService
from agent_ledger.signatures.envelope import LocalKeyring
from agent_ledger.temporal.store import LedgerStore

UTC = timezone.utc
BASE = datetime(2026, 11, 12, 0, 0, tzinfo=UTC)
SECRET = "synthetic-test-signing-secret-12345"
KEY_ID = "test-developer-key"


def timestamp(hours: int = 0, minutes: int = 0, days: int = 0) -> str:
    value = BASE + timedelta(days=days, hours=hours, minutes=minutes)
    return value.isoformat().replace("+00:00", "Z")


def declaration_payload(
    declaration_id: str = "decl-base",
    *,
    action: str = "grant",
    developer_id: str = "dev.publisher",
    application_id: str = "app.market",
    agent_identity: str = "agent.assistant.001",
    capabilities: list[str] | None = None,
    regions: list[str] | None = None,
    minimum: str | None = "1.0.0",
    maximum: str | None = "3.0.0",
    effective_from: str | None = None,
    effective_until: str | None = None,
    priority: int = 10,
    inherited_from: str | None = None,
    manufacturers: list[str] | None = None,
    models: list[str] | None = None,
    os_families: list[str] | None = None,
    min_security_patch: str | None = "2026-10-01",
    managed_only: bool = False,
    reason: str | None = None,
    nonce: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    version_range: dict[str, Any] = {}
    if minimum is not None:
        version_range["minimum"] = minimum
    if maximum is not None:
        version_range["maximum"] = maximum
    device: dict[str, Any] = {
        "manufacturers": manufacturers if manufacturers is not None else ["Northstar"],
        "models": models if models is not None else ["N1"],
        "os_families": os_families if os_families is not None else ["AuroraOS"],
        "managed_only": managed_only,
    }
    if min_security_patch is not None:
        device["min_security_patch"] = min_security_patch
    return {
        "declaration_id": declaration_id,
        "developer_id": developer_id,
        "application_id": application_id,
        "agent_identity": agent_identity,
        "action": action,
        "scope": {
            "capabilities": capabilities if capabilities is not None else ["calendar.read", "contacts.lookup"],
            "regions": regions if regions is not None else ["CN"],
            "version_range": version_range,
            "device": device,
        },
        "effective_from": effective_from or timestamp(),
        "effective_until": effective_until or timestamp(days=30),
        "priority": priority,
        "inherited_from": inherited_from,
        "reason": reason or f"synthetic {action} declaration",
        "issued_at": timestamp(minutes=-5),
        "nonce": nonce or f"nonce-{declaration_id}",
        "metadata": metadata or {"source": "synthetic-test", "labels": ["fixture"]},
    }


def withdrawal_payload(
    declaration_id: str,
    target: str,
    *,
    effective_from: str | None = None,
    priority: int = 100,
) -> dict[str, Any]:
    return declaration_payload(
        declaration_id,
        action="withdraw",
        capabilities=[],
        regions=[],
        minimum=None,
        maximum=None,
        effective_from=effective_from or timestamp(days=2),
        effective_until=None,
        priority=priority,
        min_security_patch=None,
        manufacturers=[],
        models=[],
        os_families=[],
        metadata={"source": "synthetic-test", "target_declaration_id": target},
    )


def request_payload(
    request_id: str = "req-base",
    *,
    developer_id: str = "dev.publisher",
    application_id: str = "app.market",
    application_version: str = "2.0.0",
    agent_identity: str = "agent.assistant.001",
    capability: str = "calendar.read",
    region: str = "CN",
    requested_at: str | None = None,
    device_id: str | None = None,
    manufacturer: str = "Northstar",
    model: str = "N1",
    os_family: str = "AuroraOS",
    security_patch: str = "2026-11-01",
    managed: bool = True,
    attributes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "request_id": request_id,
        "developer_id": developer_id,
        "application_id": application_id,
        "application_version": application_version,
        "agent_identity": agent_identity,
        "capability": capability,
        "region": region,
        "requested_at": requested_at or timestamp(hours=1),
        "device": {
            "device_id": device_id or f"device-{request_id}",
            "manufacturer": manufacturer,
            "model": model,
            "os_family": os_family,
            "security_patch": security_patch,
            "managed": managed,
        },
        "attributes": attributes or {"channel": "distribution", "synthetic": True},
    }


class ServiceHarness:
    def __init__(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.db = self.root / "ledger.sqlite3"
        self.store = LedgerStore(self.db)
        self.keyring = LocalKeyring({KEY_ID: SECRET})
        self.parser = DeclarationParser()
        self.service = LedgerService(self.store, self.keyring, self.parser)

    def close(self) -> None:
        self.directory.cleanup()

    def sign(self, payload: dict[str, Any]):
        declaration = self.parser.parse(payload)
        return self.keyring.sign(KEY_ID, declaration.as_payload(), signed_at=declaration.issued_at)

    def ingest_declaration(self, payload: dict[str, Any], **kwargs: Any):
        return self.service.ingest_signed_declaration(self.sign(payload), **kwargs)

    def ingest_request(self, payload: dict[str, Any], **kwargs: Any):
        return self.service.ingest_request(payload, **kwargs)

    def write_json(self, name: str, value: Any) -> Path:
        path = self.root / name
        path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return path

    def __enter__(self) -> "ServiceHarness":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


def reason_codes(decision) -> set[str]:
    return {item.code for item in decision.reasons}


def assert_decision(testcase, result, expected: str, *codes: str) -> None:
    testcase.assertIsNotNone(result.decision)
    testcase.assertEqual(result.decision.status.value, expected)
    actual = reason_codes(result.decision)
    for code in codes:
        testcase.assertIn(code, actual)
