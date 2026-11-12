from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from agent_ledger.errors import ValidationError
from agent_ledger.policy.simulator import PolicySimulator
from agent_ledger.util import parse_time
from tests.support import KEY_ID, SECRET, ServiceHarness, declaration_payload, request_payload, timestamp


class PolicySimulatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = ServiceHarness()
        self.simulator = PolicySimulator(self.harness.store)

    def tearDown(self) -> None:
        self.harness.close()

    def test_proposed_grant_changes_denial_to_allow(self) -> None:
        self.harness.ingest_request(request_payload("req-sim-grant"))
        proposal = declaration_payload("decl-sim-grant")
        result = self.simulator.simulate([proposal])
        self.assertEqual(result.evaluated, 1)
        self.assertEqual(result.status_changes, 1)
        self.assertEqual(result.changes[0].before_status, "deny")
        self.assertEqual(result.changes[0].after_status, "allow")
        self.assertEqual(self.harness.store.counts()["declarations"], 0)

    def test_proposed_deny_changes_allow_to_deny(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-existing-grant", priority=10))
        self.harness.ingest_request(request_payload("req-sim-deny"))
        proposal = declaration_payload("decl-proposed-deny", action="deny", priority=20)
        result = self.simulator.simulate([proposal])
        self.assertEqual(result.changes[0].before_status, "allow")
        self.assertEqual(result.changes[0].after_status, "deny")
        codes = {item["code"] for item in result.warnings}
        self.assertIn("allow_to_deny", codes)

    def test_remove_grant_changes_allow_to_deny(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-remove-sim"))
        self.harness.ingest_request(request_payload("req-remove-sim"))
        result = self.simulator.simulate(remove_ids=["decl-remove-sim"])
        self.assertEqual(result.status_changes, 1)
        self.assertEqual(result.removed_ids, ("decl-remove-sim",))
        self.assertEqual(result.changes[0].after_reasons, ("no_active_declaration",))

    def test_unknown_remove_id_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValidationError, "unknown declarations"):
            self.simulator.simulate(remove_ids=["decl-not-found"])

    def test_duplicate_proposal_ids_are_rejected(self) -> None:
        proposal = declaration_payload("decl-duplicate-proposal")
        with self.assertRaisesRegex(ValidationError, "duplicate proposed"):
            self.simulator.simulate([proposal, dict(proposal)])

    def test_since_filters_earlier_request(self) -> None:
        self.harness.ingest_request(request_payload("req-sim-early", requested_at=timestamp(days=1)))
        self.harness.ingest_request(request_payload("req-sim-late", requested_at=timestamp(days=3)))
        proposal = declaration_payload("decl-sim-filter", effective_until=timestamp(days=10))
        result = self.simulator.simulate([proposal], since=parse_time(timestamp(days=2)))
        self.assertEqual(result.evaluated, 1)
        self.assertEqual(result.changes[0].request_id, "req-sim-late")

    def test_until_filters_later_request(self) -> None:
        self.harness.ingest_request(request_payload("req-sim-before", requested_at=timestamp(days=1)))
        self.harness.ingest_request(request_payload("req-sim-after", requested_at=timestamp(days=3)))
        proposal = declaration_payload("decl-sim-until", effective_until=timestamp(days=10))
        result = self.simulator.simulate([proposal], until=parse_time(timestamp(days=2)))
        self.assertEqual(result.evaluated, 1)
        self.assertEqual(result.changes[0].request_id, "req-sim-before")

    def test_invalid_time_window_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValidationError, "since must be earlier"):
            self.simulator.simulate(since=parse_time(timestamp(days=2)), until=parse_time(timestamp(days=1)))

    def test_explanation_change_is_counted_without_status_change(self) -> None:
        self.harness.ingest_request(request_payload("req-sim-explanation", capability="camera.capture"))
        proposal = declaration_payload("decl-sim-explanation", capabilities=["calendar.read"])
        result = self.simulator.simulate([proposal])
        self.assertEqual(result.status_changes, 0)
        self.assertEqual(result.explanation_changes, 1)
        self.assertEqual(result.changes[0].before_reasons, ("no_active_declaration",))
        self.assertEqual(result.changes[0].after_reasons, ("capability_out_of_scope",))

    def test_unchanged_request_is_counted(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-sim-existing"))
        self.harness.ingest_request(request_payload("req-sim-unchanged"))
        result = self.simulator.simulate([])
        self.assertEqual(result.unchanged, 1)
        self.assertEqual(result.changes, ())
        self.assertEqual(result.before_counts, {"allow": 1})
        self.assertEqual(result.after_counts, {"allow": 1})

    def test_blast_radius_groups_application_capability_region(self) -> None:
        self.harness.ingest_request(request_payload("req-radius-cn", region="CN"))
        self.harness.ingest_request(request_payload("req-radius-us", region="US"))
        proposal = declaration_payload("decl-radius", regions=[], effective_until=timestamp(days=10))
        result = self.simulator.blast_radius([proposal])
        self.assertEqual(result["applications"]["app.market"]["deny->allow"], 2)
        self.assertEqual(result["capabilities"]["calendar.read"]["deny->allow"], 2)
        self.assertEqual(result["regions"]["CN"]["deny->allow"], 1)
        self.assertEqual(result["regions"]["US"]["deny->allow"], 1)

    def test_validate_proposal_reports_missing_parent(self) -> None:
        proposal = declaration_payload("decl-sim-orphan", inherited_from="decl-missing")
        result = self.simulator.validate_proposals([proposal])
        self.assertFalse(result["valid"])
        self.assertEqual(result["errors"][0]["code"], "missing_parent")

    def test_validate_proposal_warns_ambiguous_conflict(self) -> None:
        grant = declaration_payload("decl-sim-grant-conflict", action="grant", priority=10)
        deny = declaration_payload("decl-sim-deny-conflict", action="deny", priority=10)
        result = self.simulator.validate_proposals([grant, deny])
        self.assertTrue(result["valid"])
        self.assertEqual(result["warnings"][0]["code"], "ambiguous_conflict")
        self.assertEqual(result["inventory"]["ambiguous_conflict_count"], 1)

    def test_replacement_warning_is_returned(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-sim-replace", priority=10))
        proposal = declaration_payload("decl-sim-replace", priority=20)
        result = self.simulator.simulate([proposal])
        codes = {item["code"] for item in result.warnings}
        self.assertIn("in_place_replacement", codes)

    def test_compare_proposals_ranks_fewer_denials_first(self) -> None:
        self.harness.ingest_request(request_payload("req-alt"))
        alternatives = {
            "allow": [declaration_payload("decl-alt-allow")],
            "deny": [declaration_payload("decl-alt-deny", action="deny")],
        }
        result = self.simulator.compare_proposals(alternatives)
        self.assertEqual(result["ranking"][0], "allow")
        self.assertEqual(result["alternatives"]["allow"]["after_counts"], {"allow": 1})
        self.assertEqual(result["alternatives"]["deny"]["after_counts"], {"deny": 1})

    def test_compare_proposals_requires_alternative(self) -> None:
        with self.assertRaisesRegex(ValidationError, "at least one"):
            self.simulator.compare_proposals({})

    def test_compare_proposals_rejects_blank_name(self) -> None:
        with self.assertRaisesRegex(ValidationError, "non-empty"):
            self.simulator.compare_proposals({"": []})

    def test_uncovered_requests_excludes_explicit_denial(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-sim-explicit-deny", action="deny", capabilities=["camera.capture"]))
        self.harness.ingest_request(request_payload("req-sim-explicit-deny", capability="camera.capture"))
        self.harness.ingest_request(request_payload("req-sim-uncovered", capability="location.read"))
        rows = self.simulator.uncovered_requests()
        self.assertEqual([item["request_id"] for item in rows], ["req-sim-uncovered"])

    def test_uncovered_requests_include_constraint_failure(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-sim-region", regions=["CN"]))
        self.harness.ingest_request(request_payload("req-sim-region", region="US"))
        rows = self.simulator.uncovered_requests()
        self.assertEqual(rows[0]["reason_codes"], ["region_out_of_scope"])

    def test_suggest_scopes_groups_repeated_uncovered_calls(self) -> None:
        self.harness.ingest_request(request_payload("req-suggest-one", capability="location.read", region="CN"))
        self.harness.ingest_request(request_payload("req-suggest-two", capability="location.read", region="US"))
        rows = self.simulator.suggest_scopes(minimum_occurrences=2)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["observed_requests"], 2)
        self.assertEqual(rows[0]["regions"], ["CN", "US"])
        self.assertIn("do not auto-authorize", rows[0]["recommendation"])

    def test_suggest_scopes_respects_minimum_occurrences(self) -> None:
        self.harness.ingest_request(request_payload("req-suggest-single", capability="location.read"))
        self.assertEqual(self.simulator.suggest_scopes(minimum_occurrences=2), [])

    def test_suggest_scopes_rejects_nonpositive_minimum(self) -> None:
        with self.assertRaisesRegex(ValidationError, "positive"):
            self.simulator.suggest_scopes(minimum_occurrences=0)

    def test_simulation_as_dict_contains_summary(self) -> None:
        self.harness.ingest_request(request_payload("req-sim-dict"))
        result = self.simulator.simulate([declaration_payload("decl-sim-dict")]).as_dict()
        self.assertEqual(result["summary"]["evaluated"], 1)
        self.assertEqual(result["summary"]["changed"], 1)
        self.assertEqual(result["proposed_ids"], ["decl-sim-dict"])

    def test_change_windows_groups_changes_by_time_bucket(self) -> None:
        self.harness.ingest_request(request_payload("req-window-one", requested_at=timestamp(days=1)))
        self.harness.ingest_request(request_payload("req-window-two", requested_at=timestamp(days=2)))
        proposal = declaration_payload("decl-window", effective_until=timestamp(days=10))
        rows = self.simulator.change_windows([proposal], since=parse_time(timestamp()), bucket_seconds=86400)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["transitions"], {"deny->allow": 1})
        self.assertEqual(rows[1]["transitions"], {"deny->allow": 1})

    def test_change_windows_rejects_nonpositive_bucket(self) -> None:
        with self.assertRaisesRegex(ValidationError, "bucket_seconds"):
            self.simulator.change_windows(bucket_seconds=0)


class PolicySimulatorCliTests(unittest.TestCase):
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
        self.assertEqual(result.returncode, expected, msg=result.stdout + result.stderr)
        return json.loads(result.stdout)

    def test_cli_simulate_preview(self) -> None:
        self.harness.ingest_request(request_payload("req-cli-simulate"))
        path = self.harness.write_json("simulation.json", {"proposals": [declaration_payload("decl-cli-simulate")], "remove_ids": []})
        result = self.run_cli("simulate", str(path))
        self.assertEqual(result["summary"]["status_changes"], 1)
        self.assertEqual(result["changes"][0]["after_status"], "allow")

    def test_cli_simulate_blast_radius(self) -> None:
        self.harness.ingest_request(request_payload("req-cli-radius"))
        path = self.harness.write_json("simulation.json", {"proposals": [declaration_payload("decl-cli-radius")], "remove_ids": []})
        result = self.run_cli("simulate", str(path), "--blast-radius")
        self.assertEqual(result["applications"]["app.market"]["deny->allow"], 1)

    def test_cli_suggest_scopes(self) -> None:
        self.harness.ingest_request(request_payload("req-cli-suggest", capability="location.read"))
        result = self.run_cli("suggest-scopes")
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["suggestions"][0]["capability"], "location.read")


if __name__ == "__main__":
    unittest.main()
