from __future__ import annotations

import json
import unittest
from datetime import timedelta

from agent_ledger.audit.export import AuditExporter
from agent_ledger.audit.report import ComplianceReport
from agent_ledger.declarations.catalog import DeclarationCatalog
from agent_ledger.policy.matrix import PolicyMatrix
from agent_ledger.temporal.index import TemporalDeclarationIndex
from agent_ledger.temporal.query import TemporalQueryEngine
from agent_ledger.util import parse_time
from tests.support import ServiceHarness, declaration_payload, request_payload, timestamp


class AuditQueryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = ServiceHarness()

    def tearDown(self) -> None:
        self.harness.close()

    def test_snapshot_contains_ledger_revision_and_counts(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-snapshot"))
        self.harness.ingest_request(request_payload("req-snapshot"))
        snapshot = AuditExporter(self.harness.store).snapshot()
        self.assertEqual(snapshot["ledger_revision"], 2)
        self.assertEqual(snapshot["counts"]["events"], 2)
        self.assertEqual(snapshot["decision_status_counts"], {"allow": 1})

    def test_snapshot_hash_changes_with_new_event(self) -> None:
        exporter = AuditExporter(self.harness.store)
        first = exporter.snapshot()["snapshot_hash"]
        self.harness.ingest_request(request_payload("req-new-event"))
        second = exporter.snapshot()["snapshot_hash"]
        self.assertNotEqual(first, second)

    def test_json_lines_is_compact_and_round_trippable(self) -> None:
        exporter = AuditExporter(self.harness.store)
        text = exporter.json_lines([{"b": 2, "a": 1}, {"name": "合成"}])
        lines = text.splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[0]), {"a": 1, "b": 2})
        self.assertEqual(json.loads(lines[1]), {"name": "合成"})

    def test_declaration_timeline_returns_constraints(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-timeline-export", priority=33))
        rows = AuditExporter(self.harness.store).declaration_timeline("dev.publisher", "app.market", "agent.assistant.001")
        self.assertEqual(rows[0]["declaration_id"], "decl-timeline-export")
        self.assertEqual(rows[0]["priority"], 33)
        self.assertIn("calendar.read", rows[0]["capabilities"])

    def test_compliance_summary_calculates_denial_rate(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-summary"))
        self.harness.ingest_request(request_payload("req-summary-allow"))
        self.harness.ingest_request(request_payload("req-summary-deny", capability="camera.capture"))
        summary = AuditExporter(self.harness.store).compliance_summary()
        self.assertEqual(summary["evaluated"], 2)
        self.assertEqual(summary["denial_rate"], 0.5)
        self.assertEqual(summary["applications"]["app.market"], {"allow": 1, "deny": 1})

    def test_compliance_summary_respects_since(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-summary-since", effective_until=timestamp(days=10)))
        self.harness.ingest_request(request_payload("req-before", requested_at=timestamp(days=1)))
        self.harness.ingest_request(request_payload("req-after", requested_at=timestamp(days=3)))
        summary = AuditExporter(self.harness.store).compliance_summary(parse_time(timestamp(days=2)))
        self.assertEqual(summary["evaluated"], 1)

    def test_report_flags_unbounded_region(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-region-any", regions=[]))
        report = ComplianceReport(self.harness.store).generate()
        codes = {item["code"] for item in report["findings"]}
        self.assertIn("unbounded_region", codes)

    def test_report_flags_unbounded_device(self) -> None:
        self.harness.ingest_declaration(declaration_payload(
            "decl-device-any", manufacturers=[], models=[], os_families=[], min_security_patch=None, managed_only=False
        ))
        report = ComplianceReport(self.harness.store).generate()
        codes = {item["code"] for item in report["findings"]}
        self.assertIn("unbounded_device", codes)

    def test_report_flags_old_security_patch(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-old-patch", min_security_patch="2026-11-10"))
        self.harness.ingest_request(request_payload("req-old-patch", security_patch="2026-11-01"))
        report = ComplianceReport(self.harness.store).generate()
        codes = {item["code"] for item in report["findings"]}
        self.assertIn("device_patch_noncompliance", codes)

    def test_report_orders_high_before_low(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-order", regions=[]))
        self.harness.ingest_request(request_payload("req-order", capability="camera.capture"))
        report = ComplianceReport(self.harness.store).generate()
        severities = [item["severity"] for item in report["findings"]]
        ranks = [{"high": 1, "medium": 2, "low": 3, "info": 4}[item] for item in severities]
        self.assertEqual(ranks, sorted(ranks))

    def test_query_explain_lists_failed_dimensions(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-explain", regions=["CN"], models=["N1"]))
        self.harness.ingest_request(request_payload("req-explain", region="US", model="N2"))
        result = TemporalQueryEngine(self.harness.store).decision_at("req-explain")
        candidate = result["candidates"][0]
        self.assertFalse(candidate["match"]["matched"])
        self.assertFalse(candidate["match"]["dimensions"]["region"])
        self.assertFalse(candidate["match"]["dimensions"]["model"])

    def test_query_decision_at_override_does_not_mutate_stored_request(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-at", effective_from=timestamp(days=1), effective_until=timestamp(days=3)))
        self.harness.ingest_request(request_payload("req-at", requested_at=timestamp(days=2)))
        query = TemporalQueryEngine(self.harness.store)
        before = query.decision_at("req-at", parse_time(timestamp()))
        stored = self.harness.store.get_request_payload("req-at")
        self.assertEqual(before["decision"]["status"], "deny")
        self.assertEqual(parse_time(stored["requested_at"]), parse_time(timestamp(days=2)))

    def test_coverage_shows_uncovered_gap(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-gap-left", effective_until=timestamp(days=1)))
        self.harness.ingest_declaration(declaration_payload("decl-gap-right", effective_from=timestamp(days=2), effective_until=timestamp(days=3)))
        rows = TemporalQueryEngine(self.harness.store).declaration_coverage(
            "dev.publisher", "app.market", "agent.assistant.001", "calendar.read", "CN", "2.0.0",
            parse_time(timestamp()), parse_time(timestamp(days=3)),
        )
        self.assertEqual(len(rows), 3)
        self.assertTrue(rows[0]["covered"])
        self.assertFalse(rows[1]["covered"])
        self.assertTrue(rows[2]["covered"])

    def test_catalog_missing_parent_is_reported(self) -> None:
        declaration = self.harness.parser.parse(declaration_payload("decl-orphan", inherited_from="decl-missing"))
        graph = DeclarationCatalog([declaration]).inheritance_graph()
        self.assertEqual(graph["missing_parents"], {"decl-orphan": "decl-missing"})

    def test_catalog_overlap_records_region_intersection(self) -> None:
        left = self.harness.parser.parse(declaration_payload("decl-overlap-left", regions=["CN", "US"]))
        right = self.harness.parser.parse(declaration_payload("decl-overlap-right", regions=["US", "DE"]))
        overlap = DeclarationCatalog([left, right]).find_overlaps()[0]
        self.assertEqual(overlap.region_overlap, ("US",))

    def test_matrix_groups_managed_posture(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-managed-matrix", managed_only=False))
        requests = [
            self.harness.parser.parse_request(request_payload("req-managed-yes", managed=True)),
            self.harness.parser.parse_request(request_payload("req-managed-no", managed=False)),
        ]
        cells = PolicyMatrix(self.harness.service.evaluator, self.harness.store).evaluate(requests, ("managed",))
        self.assertEqual({cell.key[0] for cell in cells}, {"managed", "unmanaged"})
        self.assertTrue(all(cell.allowed == 1 for cell in cells))

    def test_matrix_reason_counts_capture_denial(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-matrix-reason", regions=["CN"]))
        request = self.harness.parser.parse_request(request_payload("req-matrix-reason", region="US"))
        cell = PolicyMatrix(self.harness.service.evaluator, self.harness.store).evaluate([request], ("region",))[0]
        self.assertEqual(cell.reason_counts, {"region_out_of_scope": 1})

    def test_matrix_allow_rate_is_fraction(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-rate"))
        requests = [
            self.harness.parser.parse_request(request_payload("req-rate-1")),
            self.harness.parser.parse_request(request_payload("req-rate-2", capability="camera.capture")),
        ]
        cells = PolicyMatrix(self.harness.service.evaluator, self.harness.store).evaluate(requests, ("application_id",))
        self.assertEqual(cells[0].allow_rate, 0.5)

    def test_compare_times_reports_changed_request(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-compare", effective_from=timestamp(days=1), effective_until=timestamp(days=3)))
        request = self.harness.parser.parse_request(request_payload("req-compare"))
        result = PolicyMatrix(self.harness.service.evaluator, self.harness.store).compare_times(
            [request], parse_time(timestamp()), parse_time(timestamp(days=2))
        )
        self.assertEqual(result["unchanged"], 0)
        self.assertEqual(len(result["changed"]), 1)

    def test_application_timeline_empty_buckets_are_preserved(self) -> None:
        rows = TemporalQueryEngine(self.harness.store).application_timeline(
            "dev.publisher", "app.market", parse_time(timestamp()), parse_time(timestamp(days=2)), timedelta(hours=12)
        )
        self.assertEqual(len(rows), 4)
        self.assertTrue(all(row["total"] == 0 for row in rows))

    def test_audit_records_filter_by_subject(self) -> None:
        self.harness.ingest_request(request_payload("req-filter-one"))
        self.harness.ingest_request(request_payload("req-filter-two"))
        records = self.harness.store.audit_records("req-filter-one")
        self.assertTrue(records)
        self.assertTrue(all(item["subject_id"] == "req-filter-one" for item in records))

    def test_counts_include_recompute_queue(self) -> None:
        self.harness.ingest_request(request_payload("req-count-queue", requested_at=timestamp(days=2)))
        self.harness.ingest_declaration(
            declaration_payload("decl-count-queue", effective_from=timestamp(days=1), effective_until=timestamp(days=3)),
            received_at=parse_time(timestamp(days=4)),
        )
        counts = self.harness.store.counts()
        self.assertEqual(counts["recompute_queue"], 1)
        self.assertEqual(counts["events"], 2)


if __name__ == "__main__":
    unittest.main()
