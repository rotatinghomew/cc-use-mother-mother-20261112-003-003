from __future__ import annotations

import unittest

from agent_ledger.models import DecisionStatus
from agent_ledger.policy.matrix import PolicyMatrix
from tests.support import ServiceHarness, assert_decision, declaration_payload, reason_codes, request_payload, timestamp


class PolicyMatrixTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = ServiceHarness()

    def tearDown(self) -> None:
        self.harness.close()

    def test_matching_grant_allows(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-allow"))
        result = self.harness.ingest_request(request_payload("req-allow"))
        assert_decision(self, result, "allow", "declared_consent")

    def test_no_declaration_denies(self) -> None:
        result = self.harness.ingest_request(request_payload("req-none"))
        assert_decision(self, result, "deny", "no_active_declaration")

    def test_explicit_deny_wins(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-deny", action="deny"))
        result = self.harness.ingest_request(request_payload("req-deny"))
        assert_decision(self, result, "deny", "explicit_denial")

    def test_equal_rank_deny_breaks_tie(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-grant", action="grant", priority=10))
        self.harness.ingest_declaration(declaration_payload("decl-deny", action="deny", priority=10))
        result = self.harness.ingest_request(request_payload("req-tie"))
        assert_decision(self, result, "deny", "explicit_denial", "deny_breaks_tie")

    def test_higher_priority_grant_beats_lower_deny(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-grant", action="grant", priority=20))
        self.harness.ingest_declaration(declaration_payload("decl-deny", action="deny", priority=10))
        result = self.harness.ingest_request(request_payload("req-priority"))
        assert_decision(self, result, "allow", "declared_consent")
        self.assertEqual(result.decision.matched_declarations, ("decl-grant",))

    def test_more_specific_grant_beats_wildcard_deny(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-wild-deny", action="deny", application_id="*", priority=10))
        self.harness.ingest_declaration(declaration_payload("decl-specific-grant", action="grant", priority=10))
        result = self.harness.ingest_request(request_payload("req-specific"))
        assert_decision(self, result, "allow")

    def test_capability_out_of_scope_denies(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-cap", capabilities=["calendar.read"]))
        result = self.harness.ingest_request(request_payload("req-cap", capability="camera.capture"))
        assert_decision(self, result, "deny", "capability_out_of_scope")

    def test_region_out_of_scope_denies(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-region", regions=["CN"]))
        result = self.harness.ingest_request(request_payload("req-region", region="US"))
        assert_decision(self, result, "deny", "region_out_of_scope")

    def test_empty_region_scope_matches_any_region(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-global", regions=[]))
        result = self.harness.ingest_request(request_payload("req-global", region="US"))
        assert_decision(self, result, "allow")

    def test_version_below_minimum_denies(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-version", minimum="2.0.0", maximum="3.0.0"))
        result = self.harness.ingest_request(request_payload("req-version-low", application_version="1.9.9"))
        assert_decision(self, result, "deny", "version_out_of_scope")

    def test_version_above_maximum_denies(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-version", minimum="1.0.0", maximum="2.0.0"))
        result = self.harness.ingest_request(request_payload("req-version-high", application_version="2.0.1"))
        assert_decision(self, result, "deny", "version_out_of_scope")

    def test_version_boundary_allows(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-version", minimum="2.0.0", maximum="2.0.0"))
        result = self.harness.ingest_request(request_payload("req-version-edge", application_version="2.0.0"))
        assert_decision(self, result, "allow")

    def test_manufacturer_constraint_denies(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-maker", manufacturers=["Northstar"]))
        result = self.harness.ingest_request(request_payload("req-maker", manufacturer="OtherCorp"))
        assert_decision(self, result, "deny", "manufacturer_out_of_scope")

    def test_model_constraint_denies(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-model", models=["N1"]))
        result = self.harness.ingest_request(request_payload("req-model", model="N2"))
        assert_decision(self, result, "deny", "model_out_of_scope")

    def test_os_constraint_denies(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-os", os_families=["AuroraOS"]))
        result = self.harness.ingest_request(request_payload("req-os", os_family="OtherOS"))
        assert_decision(self, result, "deny", "os_out_of_scope")

    def test_security_patch_constraint_denies(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-patch", min_security_patch="2026-11-01"))
        result = self.harness.ingest_request(request_payload("req-patch", security_patch="2026-10-31"))
        assert_decision(self, result, "deny", "security_patch_too_old")

    def test_managed_only_constraint_denies(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-managed", managed_only=True))
        result = self.harness.ingest_request(request_payload("req-managed", managed=False))
        assert_decision(self, result, "deny", "managed_device_required")

    def test_multiple_constraint_failures_are_explained(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-multi", regions=["CN"], models=["N1"], managed_only=True))
        result = self.harness.ingest_request(request_payload("req-multi", region="US", model="N2", managed=False))
        codes = reason_codes(result.decision)
        self.assertIn("region_out_of_scope", codes)
        self.assertIn("model_out_of_scope", codes)
        self.assertIn("managed_device_required", codes)

    def test_inherited_grant_requires_parent_scope(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-parent", application_id="*", capabilities=["calendar.read"]))
        self.harness.ingest_declaration(declaration_payload("decl-child", inherited_from="decl-parent", capabilities=["camera.capture"], priority=20))
        result = self.harness.ingest_request(request_payload("req-child", capability="camera.capture"))
        assert_decision(self, result, "deny", "invalid_inheritance")

    def test_inherited_grant_allows_when_parent_covers(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-parent", application_id="*", capabilities=["calendar.read"]))
        self.harness.ingest_declaration(declaration_payload("decl-child", inherited_from="decl-parent", capabilities=["calendar.read"], priority=20))
        result = self.harness.ingest_request(request_payload("req-child"))
        assert_decision(self, result, "allow")

    def test_parent_deny_invalidates_child_grant(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-parent", action="deny", application_id="*"))
        self.harness.ingest_declaration(declaration_payload("decl-child", action="grant", inherited_from="decl-parent", priority=20))
        result = self.harness.ingest_request(request_payload("req-child-deny"))
        assert_decision(self, result, "deny", "explicit_denial")
        candidates = self.harness.service.evaluator.explain_candidates(self.harness.parser.parse_request(request_payload("req-child-explain")))
        child = next(item for item in candidates if item["declaration_id"] == "decl-child")
        self.assertFalse(child["inherited_valid"])
        self.assertIn("explicitly denies", child["inheritance_reason"])

    def test_expired_parent_invalidates_child(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-parent", application_id="*", effective_until=timestamp(days=1)))
        self.harness.ingest_declaration(declaration_payload("decl-child", inherited_from="decl-parent", effective_until=timestamp(days=3), priority=20))
        result = self.harness.ingest_request(request_payload("req-expired-parent", requested_at=timestamp(days=2)))
        assert_decision(self, result, "deny", "invalid_inheritance")

    def test_batch_evaluate_mixes_allow_and_deny(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-batch"))
        result = self.harness.service.batch_evaluate([
            request_payload("req-batch-allow"),
            request_payload("req-batch-deny", capability="camera.capture"),
        ])
        self.assertEqual(result.allowed, 1)
        self.assertEqual(result.denied, 1)
        self.assertEqual(len(result.errors), 0)

    def test_batch_evaluate_collects_validation_errors(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-batch-errors"))
        invalid = request_payload("req-invalid")
        invalid["region"] = "bad-region"
        result = self.harness.service.batch_evaluate([request_payload("req-valid"), invalid])
        self.assertEqual(len(result.decisions), 1)
        self.assertEqual(len(result.errors), 1)
        self.assertEqual(result.errors[0]["index"], 1)

    def test_policy_matrix_groups_by_application_and_capability(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-matrix"))
        requests = [
            self.harness.parser.parse_request(request_payload("req-m1")),
            self.harness.parser.parse_request(request_payload("req-m2")),
            self.harness.parser.parse_request(request_payload("req-m3", capability="camera.capture")),
        ]
        matrix = PolicyMatrix(self.harness.service.evaluator, self.harness.store)
        cells = matrix.evaluate(requests, ("application_id", "capability"))
        self.assertEqual(len(cells), 2)
        calendar = next(item for item in cells if item.key[1] == "calendar.read")
        camera = next(item for item in cells if item.key[1] == "camera.capture")
        self.assertEqual(calendar.allowed, 2)
        self.assertEqual(camera.denied, 1)

    def test_policy_matrix_can_group_by_status(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-matrix-status"))
        requests = [
            self.harness.parser.parse_request(request_payload("req-s1")),
            self.harness.parser.parse_request(request_payload("req-s2", capability="camera.capture")),
        ]
        cells = PolicyMatrix(self.harness.service.evaluator, self.harness.store).evaluate(requests, ("status",))
        self.assertEqual({item.key[0] for item in cells}, {"allow", "deny"})

    def test_decision_is_deterministic_at_same_revision(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-deterministic"))
        request = self.harness.parser.parse_request(request_payload("req-deterministic"))
        first = self.harness.service.evaluator.evaluate(request, self.harness.store.revision())
        second = self.harness.service.evaluator.evaluate(request, self.harness.store.revision(), decided_at=first.decided_at)
        self.assertEqual(first.decision_id, second.decision_id)
        self.assertEqual(first.as_dict(), second.as_dict())


if __name__ == "__main__":
    unittest.main()
