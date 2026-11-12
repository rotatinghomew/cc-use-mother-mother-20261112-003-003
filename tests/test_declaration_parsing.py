from __future__ import annotations

import unittest

from agent_ledger.declarations.parser import DeclarationParser
from agent_ledger.errors import ValidationError
from agent_ledger.models import DeclarationAction
from agent_ledger.signatures.envelope import LocalKeyring
from tests.support import KEY_ID, SECRET, declaration_payload, request_payload, timestamp, withdrawal_payload


class DeclarationParsingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = DeclarationParser()

    def test_parses_full_grant(self) -> None:
        value = declaration_payload("decl-full", managed_only=True, priority=77)
        declaration = self.parser.parse(value)
        self.assertEqual(declaration.declaration_id, "decl-full")
        self.assertEqual(declaration.action, DeclarationAction.GRANT)
        self.assertEqual(declaration.priority, 77)
        self.assertEqual(declaration.scope.capabilities, ("calendar.read", "contacts.lookup"))
        self.assertEqual(declaration.scope.regions, ("CN",))
        self.assertTrue(declaration.scope.device.managed_only)
        self.assertEqual(declaration.scope.version_range.minimum, "1.0.0")
        self.assertEqual(declaration.scope.version_range.maximum, "3.0.0")

    def test_normalizes_duplicate_capabilities(self) -> None:
        value = declaration_payload("decl-dupe", capabilities=["contacts.lookup", "calendar.read", "contacts.lookup"])
        declaration = self.parser.parse(value)
        self.assertEqual(declaration.scope.capabilities, ("calendar.read", "contacts.lookup"))

    def test_allows_wildcard_selectors(self) -> None:
        value = declaration_payload("decl-wild", application_id="*", agent_identity="*")
        declaration = self.parser.parse(value)
        self.assertEqual(declaration.application_id, "*")
        self.assertEqual(declaration.agent_identity, "*")

    def test_rejects_empty_grant_capabilities(self) -> None:
        value = declaration_payload("decl-empty", capabilities=[])
        with self.assertRaisesRegex(ValidationError, "require capabilities"):
            self.parser.parse(value)

    def test_withdrawal_can_have_empty_capabilities(self) -> None:
        declaration = self.parser.parse(withdrawal_payload("withdraw-1", "decl-base"))
        self.assertEqual(declaration.action, DeclarationAction.WITHDRAW)
        self.assertEqual(declaration.scope.capabilities, ())
        self.assertEqual(declaration.metadata["target_declaration_id"], "decl-base")

    def test_rejects_reverse_effective_interval(self) -> None:
        value = declaration_payload("decl-time", effective_from=timestamp(days=2), effective_until=timestamp(days=1))
        with self.assertRaisesRegex(ValidationError, "later than"):
            self.parser.parse(value)

    def test_rejects_equal_effective_interval(self) -> None:
        value = declaration_payload("decl-time-equal", effective_from=timestamp(days=2), effective_until=timestamp(days=2))
        with self.assertRaises(ValidationError):
            self.parser.parse(value)

    def test_rejects_naive_timestamp(self) -> None:
        value = declaration_payload("decl-naive")
        value["issued_at"] = "2026-11-12T00:00:00"
        with self.assertRaisesRegex(ValidationError, "requires an offset"):
            self.parser.parse(value)

    def test_rejects_bad_identifier(self) -> None:
        value = declaration_payload("decl bad")
        with self.assertRaisesRegex(ValidationError, "invalid identifier"):
            self.parser.parse(value)

    def test_rejects_unknown_scope_field(self) -> None:
        value = declaration_payload("decl-unknown")
        value["scope"]["unexpected"] = True
        with self.assertRaisesRegex(ValidationError, "unknown scope"):
            self.parser.parse(value)

    def test_rejects_unknown_device_field(self) -> None:
        value = declaration_payload("decl-device-unknown")
        value["scope"]["device"]["imei"] = "not-allowed"
        with self.assertRaisesRegex(ValidationError, "unknown device"):
            self.parser.parse(value)

    def test_rejects_unknown_metadata_field(self) -> None:
        value = declaration_payload("decl-meta-unknown")
        value["metadata"]["secret"] = "nope"
        with self.assertRaisesRegex(ValidationError, "unknown metadata"):
            self.parser.parse(value)

    def test_rejects_priority_outside_range(self) -> None:
        value = declaration_payload("decl-priority", priority=1001)
        with self.assertRaisesRegex(ValidationError, "priority"):
            self.parser.parse(value)

    def test_rejects_boolean_priority(self) -> None:
        value = declaration_payload("decl-priority-bool")
        value["priority"] = True
        with self.assertRaises(ValidationError):
            self.parser.parse(value)

    def test_rejects_bad_version_range(self) -> None:
        value = declaration_payload("decl-version", minimum="3.0.0", maximum="2.0.0")
        with self.assertRaisesRegex(ValidationError, "minimum exceeds"):
            self.parser.parse(value)

    def test_rejects_invalid_security_patch(self) -> None:
        value = declaration_payload("decl-patch", min_security_patch="2026-13-01")
        with self.assertRaisesRegex(ValidationError, "YYYY-MM-DD"):
            self.parser.parse(value)

    def test_generates_stable_declaration_id(self) -> None:
        value = declaration_payload("decl-remove")
        value.pop("declaration_id")
        first = self.parser.parse(value)
        second = self.parser.parse(dict(value))
        self.assertEqual(first.declaration_id, second.declaration_id)
        self.assertTrue(first.declaration_id.startswith("decl_"))

    def test_parses_request_device_context(self) -> None:
        request = self.parser.parse_request(request_payload("req-full", managed=False, region="US-CA"))
        self.assertEqual(request.request_id, "req-full")
        self.assertEqual(request.region, "US-CA")
        self.assertFalse(request.device.managed)
        self.assertEqual(request.application_version, "2.0.0")

    def test_generates_stable_request_id(self) -> None:
        value = request_payload("remove-me")
        value.pop("request_id")
        first = self.parser.parse_request(value)
        second = self.parser.parse_request(dict(value))
        self.assertEqual(first.request_id, second.request_id)
        self.assertTrue(first.request_id.startswith("req_"))

    def test_rejects_missing_device_field(self) -> None:
        value = request_payload("req-missing")
        value["device"].pop("model")
        with self.assertRaisesRegex(ValidationError, "missing fields"):
            self.parser.parse_request(value)

    def test_rejects_nested_request_attributes(self) -> None:
        value = request_payload("req-nested", attributes={"nested": {"value": 1}})
        with self.assertRaisesRegex(ValidationError, "invalid fields"):
            self.parser.parse_request(value)

    def test_rejects_too_many_attributes(self) -> None:
        value = request_payload("req-many", attributes={f"k{i}": i for i in range(33)})
        with self.assertRaisesRegex(ValidationError, "too many"):
            self.parser.parse_request(value)

    def test_sign_and_verify_round_trip(self) -> None:
        keyring = LocalKeyring({KEY_ID: SECRET})
        declaration = self.parser.parse(declaration_payload("decl-signed"))
        envelope = keyring.sign(KEY_ID, declaration.as_payload(), signed_at=declaration.issued_at)
        result = keyring.verify(envelope)
        self.assertTrue(result.valid)
        self.assertIsNone(result.failure)
        parsed = keyring.parse_envelope(envelope.as_dict())
        self.assertEqual(parsed.payload, declaration.as_payload())

    def test_signature_detects_payload_tampering(self) -> None:
        keyring = LocalKeyring({KEY_ID: SECRET})
        declaration = self.parser.parse(declaration_payload("decl-tamper"))
        envelope = keyring.sign(KEY_ID, declaration.as_payload(), signed_at=declaration.issued_at)
        data = envelope.as_dict()
        data["payload"]["priority"] = 999
        parsed = keyring.parse_envelope(data)
        result = keyring.verify(parsed)
        self.assertFalse(result.valid)
        self.assertEqual(result.failure, "signature_mismatch")

    def test_signature_rejects_unknown_key(self) -> None:
        first = LocalKeyring({KEY_ID: SECRET})
        second = LocalKeyring({"other": "another-synthetic-secret-12345"})
        declaration = self.parser.parse(declaration_payload("decl-key"))
        envelope = first.sign(KEY_ID, declaration.as_payload(), signed_at=declaration.issued_at)
        result = second.verify(envelope)
        self.assertFalse(result.valid)
        self.assertEqual(result.failure, "unknown_key")

    def test_key_rotation_replaces_old_key(self) -> None:
        keyring = LocalKeyring({KEY_ID: SECRET})
        keyring.rotate(KEY_ID, "new-key", "new-synthetic-signing-secret-12345")
        self.assertFalse(keyring.contains(KEY_ID))
        self.assertTrue(keyring.contains("new-key"))
        self.assertEqual(keyring.key_ids(), ("new-key",))


if __name__ == "__main__":
    unittest.main()
