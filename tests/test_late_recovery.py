from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock

from agent_ledger.audit.export import AuditExporter
from agent_ledger.audit.report import ComplianceReport
from agent_ledger.errors import ConflictError, SignatureError
from agent_ledger.ingest.reconcile import Reconciler
from agent_ledger.models import SignedEnvelope
from agent_ledger.temporal.query import TemporalQueryEngine
from agent_ledger.util import parse_time
from tests.support import KEY_ID, SECRET, ServiceHarness, declaration_payload, request_payload, timestamp


class LateRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = ServiceHarness()

    def tearDown(self) -> None:
        self.harness.close()

    def test_duplicate_declaration_event_is_idempotent(self) -> None:
        payload = declaration_payload("decl-idempotent")
        envelope = self.harness.sign(payload)
        first = self.harness.service.ingest_signed_declaration(envelope, event_id="evt-decl-same")
        second = self.harness.service.ingest_signed_declaration(envelope, event_id="evt-decl-same")
        self.assertTrue(first.inserted)
        self.assertFalse(second.inserted)
        self.assertEqual(self.harness.store.counts()["declarations"], 1)
        self.assertEqual(self.harness.store.counts()["events"], 1)

    def test_same_declaration_content_with_new_event_is_idempotent(self) -> None:
        payload = declaration_payload("decl-content-idempotent")
        envelope = self.harness.sign(payload)
        first = self.harness.service.ingest_signed_declaration(envelope, event_id="evt-decl-one")
        second = self.harness.service.ingest_signed_declaration(envelope, event_id="evt-decl-two")
        self.assertTrue(first.inserted)
        self.assertFalse(second.inserted)
        self.assertEqual(second.event_id, first.event_id)

    def test_declaration_id_content_conflict_is_rejected(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-conflict", priority=1), event_id="evt-conflict-one")
        with self.assertRaises(ConflictError):
            self.harness.ingest_declaration(declaration_payload("decl-conflict", priority=2), event_id="evt-conflict-two")

    def test_duplicate_request_event_is_idempotent(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-request-idempotent"))
        payload = request_payload("req-idempotent")
        first = self.harness.ingest_request(payload, event_id="evt-request-same")
        second = self.harness.ingest_request(payload, event_id="evt-request-same")
        self.assertTrue(first.inserted)
        self.assertFalse(second.inserted)
        self.assertEqual(self.harness.store.counts()["requests"], 1)

    def test_request_id_content_conflict_is_rejected(self) -> None:
        self.harness.ingest_request(request_payload("req-conflict", region="CN"), event_id="evt-req-one")
        with self.assertRaises(ConflictError):
            self.harness.ingest_request(request_payload("req-conflict", region="US"), event_id="evt-req-two")

    def test_tampered_signature_is_rejected_before_storage(self) -> None:
        payload = declaration_payload("decl-tampered")
        envelope = self.harness.sign(payload)
        tampered_payload = dict(envelope.payload)
        tampered_payload["priority"] = 999
        tampered = SignedEnvelope(envelope.key_id, envelope.algorithm, tampered_payload, envelope.signature, envelope.signed_at)
        with self.assertRaises(SignatureError):
            self.harness.service.ingest_signed_declaration(tampered)
        self.assertEqual(self.harness.store.counts()["declarations"], 0)

    def test_late_grant_queues_prior_request(self) -> None:
        request = self.harness.ingest_request(request_payload("req-late", requested_at=timestamp(days=2)))
        self.assertEqual(request.decision.status.value, "deny")
        declaration = declaration_payload("decl-late", effective_from=timestamp(days=1), effective_until=timestamp(days=3))
        result = self.harness.ingest_declaration(declaration, received_at=parse_time(timestamp(days=4)))
        self.assertTrue(result.late)
        self.assertEqual(result.queued_recomputations, 1)
        queued = self.harness.store.queued_recomputations()
        self.assertEqual([item["request_id"] for item in queued], ["req-late"])

    def test_reconcile_changes_denial_to_allow(self) -> None:
        self.harness.ingest_request(request_payload("req-reconcile", requested_at=timestamp(days=2)))
        self.harness.ingest_declaration(
            declaration_payload("decl-reconcile", effective_from=timestamp(days=1), effective_until=timestamp(days=3)),
            received_at=parse_time(timestamp(days=4)),
        )
        outcome = Reconciler(self.harness.store).run()
        self.assertEqual(outcome.processed, 1)
        self.assertEqual(outcome.changed, 1)
        current = self.harness.store.current_decision("req-reconcile")
        self.assertEqual(current.status.value, "allow")
        history = self.harness.store.decision_history("req-reconcile")
        self.assertEqual([item.status.value for item in history], ["deny", "allow"])

    def test_reconcile_clears_queue(self) -> None:
        self.harness.ingest_request(request_payload("req-clear", requested_at=timestamp(days=2)))
        self.harness.ingest_declaration(
            declaration_payload("decl-clear", effective_from=timestamp(days=1), effective_until=timestamp(days=3)),
            received_at=parse_time(timestamp(days=4)),
        )
        Reconciler(self.harness.store).run()
        self.assertEqual(self.harness.store.queued_recomputations(), [])

    def test_late_declaration_outside_request_time_queues_nothing(self) -> None:
        self.harness.ingest_request(request_payload("req-outside", requested_at=timestamp(days=5)))
        result = self.harness.ingest_declaration(
            declaration_payload("decl-outside", effective_from=timestamp(days=1), effective_until=timestamp(days=3)),
            received_at=parse_time(timestamp(days=6)),
        )
        self.assertEqual(result.queued_recomputations, 0)

    def test_late_declaration_for_other_app_queues_nothing(self) -> None:
        self.harness.ingest_request(request_payload("req-other-app", requested_at=timestamp(days=2)))
        result = self.harness.ingest_declaration(
            declaration_payload("decl-other-app", application_id="app.other", effective_from=timestamp(days=1), effective_until=timestamp(days=3)),
            received_at=parse_time(timestamp(days=4)),
        )
        self.assertEqual(result.queued_recomputations, 0)

    def test_wildcard_late_declaration_finds_matching_requests(self) -> None:
        self.harness.ingest_request(request_payload("req-wild-1", application_id="app.one", requested_at=timestamp(days=2)))
        self.harness.ingest_request(request_payload("req-wild-2", application_id="app.two", requested_at=timestamp(days=2)))
        result = self.harness.ingest_declaration(
            declaration_payload("decl-wild-late", application_id="*", effective_from=timestamp(days=1), effective_until=timestamp(days=3)),
            received_at=parse_time(timestamp(days=4)),
        )
        self.assertEqual(result.queued_recomputations, 2)

    def test_late_deny_changes_allow_to_deny(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-initial-grant", priority=10, effective_until=timestamp(days=5)))
        self.harness.ingest_request(request_payload("req-late-deny", requested_at=timestamp(days=2)))
        self.harness.ingest_declaration(
            declaration_payload("decl-late-deny", action="deny", priority=20, effective_from=timestamp(days=1), effective_until=timestamp(days=4)),
            received_at=parse_time(timestamp(days=6)),
        )
        outcome = Reconciler(self.harness.store).run()
        self.assertEqual(outcome.changed, 1)
        self.assertEqual(self.harness.store.current_decision("req-late-deny").status.value, "deny")

    def test_reconcile_updates_explanation_when_late_declaration_does_not_match_capability(self) -> None:
        self.harness.ingest_request(request_payload("req-unchanged", capability="camera.capture", requested_at=timestamp(days=2)))
        self.harness.ingest_declaration(
            declaration_payload("decl-unchanged", capabilities=["calendar.read"], effective_from=timestamp(days=1), effective_until=timestamp(days=3)),
            received_at=parse_time(timestamp(days=4)),
        )
        outcome = Reconciler(self.harness.store).run()
        self.assertEqual(outcome.unchanged, 0)
        self.assertEqual(outcome.changed, 1)
        current = self.harness.store.current_decision("req-unchanged")
        self.assertEqual(current.status.value, "deny")
        self.assertEqual({item.code for item in current.reasons}, {"capability_out_of_scope"})

    def test_full_rebuild_repairs_missing_decision(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-rebuild"))
        request = self.harness.parser.parse_request(request_payload("req-rebuild"))
        self.harness.service.ingest_request(request, persist_decision=False)
        self.assertIsNone(self.harness.store.current_decision("req-rebuild"))
        outcome = Reconciler(self.harness.store).rebuild_all()
        self.assertEqual(outcome.changed, 1)
        self.assertEqual(self.harness.store.current_decision("req-rebuild").status.value, "allow")

    def test_reconcile_records_audit_change(self) -> None:
        self.harness.ingest_request(request_payload("req-audit", requested_at=timestamp(days=2)))
        self.harness.ingest_declaration(
            declaration_payload("decl-audit", effective_from=timestamp(days=1), effective_until=timestamp(days=3)),
            received_at=parse_time(timestamp(days=4)),
        )
        Reconciler(self.harness.store).run()
        records = self.harness.store.audit_records("req-audit")
        categories = [item["category"] for item in records]
        self.assertIn("request_reconciled", categories)
        reconciled = next(item for item in records if item["category"] == "request_reconciled")
        self.assertTrue(reconciled["detail"]["changed"])

    def test_late_event_impact_reports_causes(self) -> None:
        self.harness.ingest_request(request_payload("req-impact", requested_at=timestamp(days=2)))
        result = self.harness.ingest_declaration(
            declaration_payload("decl-impact", effective_from=timestamp(days=1), effective_until=timestamp(days=3)),
            received_at=parse_time(timestamp(days=4)),
        )
        impact = TemporalQueryEngine(self.harness.store).late_event_impact()
        self.assertEqual(impact["queued_requests"], 1)
        self.assertEqual(impact["causes"][0]["event_id"], result.event_id)

    def test_atomic_batch_persists_all_requests(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-atomic"))
        result = self.harness.service.ingest_batch_requests([
            request_payload("req-atomic-1"),
            request_payload("req-atomic-2", capability="camera.capture"),
        ], atomic=True)
        self.assertTrue(result["atomic"])
        self.assertEqual(len(result["results"]), 2)
        self.assertEqual(self.harness.store.counts()["requests"], 2)

    def test_atomic_batch_validation_failure_writes_nothing(self) -> None:
        invalid = request_payload("req-invalid-atomic")
        invalid["region"] = "bad"
        with self.assertRaises(Exception):
            self.harness.service.ingest_batch_requests([request_payload("req-valid-atomic"), invalid], atomic=True)
        self.assertEqual(self.harness.store.counts()["requests"], 0)

    def test_non_atomic_batch_keeps_valid_request(self) -> None:
        invalid = request_payload("req-invalid-nonatomic")
        invalid["region"] = "bad"
        result = self.harness.service.ingest_batch_requests([request_payload("req-valid-nonatomic"), invalid], atomic=False)
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(len(result["errors"]), 1)
        self.assertEqual(self.harness.store.counts()["requests"], 1)

    def test_export_snapshot_hash_verifies(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-export"))
        self.harness.ingest_request(request_payload("req-export"))
        exporter = AuditExporter(self.harness.store)
        snapshot = exporter.snapshot()
        self.assertTrue(exporter.verify_snapshot(snapshot))
        snapshot["ledger_revision"] += 1
        self.assertFalse(exporter.verify_snapshot(snapshot))

    def test_export_json_writes_auditable_file(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-export-json"))
        self.harness.ingest_request(request_payload("req-export-json"))
        path = self.harness.root / "audit.json"
        result = AuditExporter(self.harness.store).export_json(path)
        self.assertEqual(result["path"], str(path))
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(len(data["declarations"]), 1)
        self.assertEqual(len(data["decisions"]), 1)

    def test_export_csv_writes_decision_rows(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-export-csv"))
        self.harness.ingest_request(request_payload("req-export-csv"))
        path = self.harness.root / "decisions.csv"
        result = AuditExporter(self.harness.store).export_decisions_csv(path)
        self.assertEqual(result["rows"], 1)
        text = path.read_text(encoding="utf-8")
        self.assertIn("req-export-csv", text)
        self.assertIn("declared_consent", text)

    def test_compliance_report_flags_undeclared_call(self) -> None:
        self.harness.ingest_request(request_payload("req-undeclared"))
        report = ComplianceReport(self.harness.store).generate()
        codes = {item["code"] for item in report["findings"]}
        self.assertIn("undeclared_call", codes)

    def test_compliance_report_flags_broad_selector(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-broad", application_id="*", agent_identity="*"))
        report = ComplianceReport(self.harness.store).generate()
        codes = {item["code"] for item in report["findings"]}
        self.assertIn("broad_selector", codes)

    def test_compliance_report_counts_statuses(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-report"))
        self.harness.ingest_request(request_payload("req-report-allow"))
        self.harness.ingest_request(request_payload("req-report-deny", capability="camera.capture"))
        report = ComplianceReport(self.harness.store).generate()
        self.assertEqual(report["status_counts"], {"allow": 1, "deny": 1})

    def test_decision_diff_detects_time_change(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-diff", effective_from=timestamp(days=1), effective_until=timestamp(days=3)))
        self.harness.ingest_request(request_payload("req-diff", requested_at=timestamp(days=2)))
        diff = TemporalQueryEngine(self.harness.store).decision_diff("req-diff", parse_time(timestamp()), parse_time(timestamp(days=2)))
        self.assertTrue(diff["status_changed"])
        self.assertEqual(diff["first"]["decision"]["status"], "deny")
        self.assertEqual(diff["second"]["decision"]["status"], "allow")

    def test_reconcile_failure_is_retained_for_retry(self) -> None:
        self.harness.ingest_request(request_payload("req-fail-reconcile", requested_at=timestamp(days=2)))
        self.harness.ingest_declaration(
            declaration_payload("decl-fail-reconcile", effective_from=timestamp(days=1), effective_until=timestamp(days=3)),
            received_at=parse_time(timestamp(days=4)),
        )
        original = self.harness.store.get_request_payload
        with mock.patch.object(self.harness.store, "get_request_payload", side_effect=RuntimeError("synthetic failure")):
            outcome = Reconciler(self.harness.store).run()
        self.assertEqual(outcome.failed, 1)
        queued = self.harness.store.queued_recomputations()
        self.assertEqual(queued[0]["attempts"], 1)
        self.assertIn("synthetic failure", queued[0]["last_error"])
        self.assertEqual(original("req-fail-reconcile")["request_id"], "req-fail-reconcile")


class CliIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = ServiceHarness()
        self.project = Path(__file__).resolve().parents[1]
        self.env = dict(os.environ)
        self.env["PYTHONPATH"] = str(self.project)

    def tearDown(self) -> None:
        self.harness.close()

    def run_cli(self, *arguments: str, expected: int = 0) -> dict:
        command = [sys.executable, "-m", "agent_ledger", "--db", str(self.harness.db), "--key-id", KEY_ID, "--secret", SECRET, *arguments]
        result = subprocess.run(command, cwd=self.project, env=self.env, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, expected, msg=result.stderr + result.stdout)
        return json.loads(result.stdout)

    def test_cli_init(self) -> None:
        result = self.run_cli("init")
        self.assertEqual(result["counts"]["events"], 0)
        self.assertEqual(result["key_id"], KEY_ID)

    def test_cli_sign_and_ingest(self) -> None:
        declaration_path = self.harness.write_json("declaration.json", declaration_payload("decl-cli"))
        signed_path = self.harness.root / "signed.json"
        signed_result = self.run_cli("sign", str(declaration_path), "--output", str(signed_path))
        self.assertEqual(signed_result["declaration_id"], "decl-cli")
        ingest_result = self.run_cli("ingest-declaration", str(signed_path))
        self.assertTrue(ingest_result["inserted"])
        request_path = self.harness.write_json("request.json", request_payload("req-cli"))
        request_result = self.run_cli("ingest-request", str(request_path))
        self.assertEqual(request_result["decision"]["status"], "allow")

    def test_cli_batch_evaluate(self) -> None:
        declaration_path = self.harness.write_json("declaration.json", declaration_payload("decl-cli-batch"))
        signed_path = self.harness.root / "signed.json"
        self.run_cli("sign", str(declaration_path), "--output", str(signed_path))
        self.run_cli("ingest-declaration", str(signed_path))
        batch_path = self.harness.write_json("batch.json", [request_payload("req-cli-b1"), request_payload("req-cli-b2", capability="camera.capture")])
        result = self.run_cli("batch", str(batch_path))
        self.assertEqual(result["summary"]["allowed"], 1)
        self.assertEqual(result["summary"]["denied"], 1)

    def test_cli_report_and_export(self) -> None:
        request_path = self.harness.write_json("request.json", request_payload("req-cli-report"))
        self.run_cli("ingest-request", str(request_path))
        report = self.run_cli("report")
        self.assertEqual(report["status_counts"], {"deny": 1})
        output = self.harness.root / "export.json"
        result = self.run_cli("export", str(output))
        self.assertTrue(output.exists())
        self.assertIn("snapshot_hash", result)

    def test_cli_invalid_input_returns_error(self) -> None:
        path = self.harness.write_json("invalid.json", {"not": "a request"})
        result = self.run_cli("ingest-request", str(path), expected=2)
        self.assertEqual(result["error"]["code"], "validation_error")


if __name__ == "__main__":
    unittest.main()
