from __future__ import annotations

import unittest
from datetime import timedelta

from agent_ledger.declarations.catalog import DeclarationCatalog
from agent_ledger.temporal.index import TemporalDeclarationIndex
from agent_ledger.temporal.query import TemporalQueryEngine
from agent_ledger.util import parse_time
from tests.support import ServiceHarness, declaration_payload, request_payload, timestamp, withdrawal_payload


class TemporalJoinTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = ServiceHarness()

    def tearDown(self) -> None:
        self.harness.close()

    def test_active_declaration_at_start_boundary(self) -> None:
        declaration = self.harness.parser.parse(declaration_payload("decl-boundary"))
        index = TemporalDeclarationIndex([declaration])
        active = index.active("dev.publisher", "app.market", "agent.assistant.001", parse_time(timestamp()))
        self.assertEqual([item.declaration_id for item in active], ["decl-boundary"])

    def test_declaration_inactive_at_end_boundary(self) -> None:
        declaration = self.harness.parser.parse(declaration_payload("decl-end", effective_until=timestamp(days=1)))
        index = TemporalDeclarationIndex([declaration])
        active = index.active("dev.publisher", "app.market", "agent.assistant.001", parse_time(timestamp(days=1)))
        self.assertEqual(active, ())

    def test_before_start_has_no_active_declaration(self) -> None:
        declaration = self.harness.parser.parse(declaration_payload("decl-future", effective_from=timestamp(days=1)))
        index = TemporalDeclarationIndex([declaration])
        active = index.active("dev.publisher", "app.market", "agent.assistant.001", parse_time(timestamp()))
        self.assertEqual(active, ())

    def test_application_wildcard_matches(self) -> None:
        declaration = self.harness.parser.parse(declaration_payload("decl-app-wild", application_id="*"))
        index = TemporalDeclarationIndex([declaration])
        active = index.active("dev.publisher", "app.other", "agent.assistant.001", parse_time(timestamp(hours=1)))
        self.assertEqual(len(active), 1)

    def test_agent_wildcard_matches(self) -> None:
        declaration = self.harness.parser.parse(declaration_payload("decl-agent-wild", agent_identity="*"))
        index = TemporalDeclarationIndex([declaration])
        active = index.active("dev.publisher", "app.market", "agent.other.002", parse_time(timestamp(hours=1)))
        self.assertEqual(len(active), 1)

    def test_other_developer_does_not_match(self) -> None:
        declaration = self.harness.parser.parse(declaration_payload("decl-dev"))
        index = TemporalDeclarationIndex([declaration])
        active = index.active("dev.other", "app.market", "agent.assistant.001", parse_time(timestamp(hours=1)))
        self.assertEqual(active, ())

    def test_priority_orders_active_declarations(self) -> None:
        low = self.harness.parser.parse(declaration_payload("decl-low", priority=1))
        high = self.harness.parser.parse(declaration_payload("decl-high", priority=100))
        index = TemporalDeclarationIndex([low, high])
        active = index.active("dev.publisher", "app.market", "agent.assistant.001", parse_time(timestamp(hours=1)))
        self.assertEqual([item.declaration_id for item in active], ["decl-high", "decl-low"])

    def test_specific_declaration_ranks_above_wildcard(self) -> None:
        wildcard = self.harness.parser.parse(declaration_payload("decl-wild", application_id="*", priority=5))
        specific = self.harness.parser.parse(declaration_payload("decl-specific", priority=5))
        index = TemporalDeclarationIndex([wildcard, specific])
        active = index.active("dev.publisher", "app.market", "agent.assistant.001", parse_time(timestamp(hours=1)))
        self.assertEqual(active[0].declaration_id, "decl-specific")

    def test_withdrawal_removes_target_after_effective_time(self) -> None:
        grant = self.harness.parser.parse(declaration_payload("decl-target", effective_until=timestamp(days=10)))
        withdrawal = self.harness.parser.parse(withdrawal_payload("withdraw-target", "decl-target", effective_from=timestamp(days=2)))
        index = TemporalDeclarationIndex([grant, withdrawal])
        before = index.active("dev.publisher", "app.market", "agent.assistant.001", parse_time(timestamp(days=1)))
        after = index.active("dev.publisher", "app.market", "agent.assistant.001", parse_time(timestamp(days=3)))
        self.assertIn("decl-target", [item.declaration_id for item in before])
        self.assertNotIn("decl-target", [item.declaration_id for item in after])

    def test_withdrawal_not_retroactive(self) -> None:
        grant = self.harness.parser.parse(declaration_payload("decl-retro", effective_until=timestamp(days=10)))
        withdrawal = self.harness.parser.parse(withdrawal_payload("withdraw-retro", "decl-retro", effective_from=timestamp(days=2)))
        index = TemporalDeclarationIndex([grant, withdrawal])
        active = index.active("dev.publisher", "app.market", "agent.assistant.001", parse_time(timestamp(days=1, hours=23)))
        self.assertIn("decl-retro", [item.declaration_id for item in active])

    def test_inheritance_chain_returns_parent_order(self) -> None:
        root = self.harness.parser.parse(declaration_payload("decl-root", application_id="*"))
        child = self.harness.parser.parse(declaration_payload("decl-child", inherited_from="decl-root"))
        grandchild = self.harness.parser.parse(declaration_payload("decl-grandchild", inherited_from="decl-child", priority=20))
        index = TemporalDeclarationIndex([root, child, grandchild])
        chain = index.chain(grandchild)
        self.assertEqual([item.declaration_id for item in chain], ["decl-grandchild", "decl-child", "decl-root"])

    def test_descendants_are_discovered(self) -> None:
        root = self.harness.parser.parse(declaration_payload("decl-root"))
        child = self.harness.parser.parse(declaration_payload("decl-child", inherited_from="decl-root"))
        grandchild = self.harness.parser.parse(declaration_payload("decl-grandchild", inherited_from="decl-child"))
        index = TemporalDeclarationIndex([root, child, grandchild])
        descendants = index.descendants("decl-root")
        self.assertEqual({item.declaration_id for item in descendants}, {"decl-child", "decl-grandchild"})

    def test_remove_updates_timeline(self) -> None:
        declaration = self.harness.parser.parse(declaration_payload("decl-remove"))
        index = TemporalDeclarationIndex([declaration])
        self.assertTrue(index.remove("decl-remove"))
        self.assertFalse(index.remove("decl-remove"))
        self.assertEqual(index.all(), ())

    def test_timeline_is_chronological(self) -> None:
        late = self.harness.parser.parse(declaration_payload("decl-late", effective_from=timestamp(days=2)))
        early = self.harness.parser.parse(declaration_payload("decl-early", effective_from=timestamp(days=1)))
        index = TemporalDeclarationIndex([late, early])
        timeline = index.timeline("dev.publisher", "app.market", "agent.assistant.001")
        self.assertEqual([item.declaration.declaration_id for item in timeline], ["decl-early", "decl-late"])

    def test_catalog_detects_action_conflict(self) -> None:
        grant = self.harness.parser.parse(declaration_payload("decl-grant", action="grant", priority=10))
        deny = self.harness.parser.parse(declaration_payload("decl-deny", action="deny", priority=10))
        catalog = DeclarationCatalog([grant, deny])
        conflicts = catalog.conflicts()
        self.assertEqual(len(conflicts), 1)
        self.assertTrue(conflicts[0].conflicting_action)
        self.assertTrue(conflicts[0].same_rank)

    def test_catalog_ignores_nonoverlapping_capabilities(self) -> None:
        left = self.harness.parser.parse(declaration_payload("decl-left", capabilities=["calendar.read"]))
        right = self.harness.parser.parse(declaration_payload("decl-right", capabilities=["location.read"]))
        catalog = DeclarationCatalog([left, right])
        self.assertEqual(catalog.find_overlaps(), ())

    def test_catalog_ignores_nonoverlapping_time(self) -> None:
        left = self.harness.parser.parse(declaration_payload("decl-left", effective_until=timestamp(days=1)))
        right = self.harness.parser.parse(declaration_payload("decl-right", effective_from=timestamp(days=1), effective_until=timestamp(days=2)))
        catalog = DeclarationCatalog([left, right])
        self.assertEqual(catalog.find_overlaps(), ())

    def test_catalog_inventory_counts_actions(self) -> None:
        grant = self.harness.parser.parse(declaration_payload("decl-grant"))
        deny = self.harness.parser.parse(declaration_payload("decl-deny", action="deny"))
        catalog = DeclarationCatalog([grant, deny])
        inventory = catalog.inventory()
        self.assertEqual(inventory["total"], 2)
        self.assertEqual(inventory["actions"], {"deny": 1, "grant": 1})

    def test_catalog_inheritance_graph_reports_depth(self) -> None:
        root = self.harness.parser.parse(declaration_payload("decl-root"))
        child = self.harness.parser.parse(declaration_payload("decl-child", inherited_from="decl-root"))
        catalog = DeclarationCatalog([root, child])
        graph = catalog.inheritance_graph()
        self.assertEqual(graph["roots"], ["decl-root"])
        self.assertEqual(graph["children"]["decl-root"], ["decl-child"])
        self.assertEqual(graph["max_depth"], 2)

    def test_coverage_splits_on_declaration_boundaries(self) -> None:
        first = self.harness.parser.parse(declaration_payload("decl-first", effective_until=timestamp(days=2)))
        second = self.harness.parser.parse(declaration_payload("decl-second", effective_from=timestamp(days=2), effective_until=timestamp(days=4)))
        catalog = DeclarationCatalog([first, second])
        rows = catalog.coverage(
            "dev.publisher", "app.market", "agent.assistant.001", "calendar.read", "CN", "2.0.0",
            parse_time(timestamp()), parse_time(timestamp(days=4)),
        )
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["grant_ids"], ["decl-first"])
        self.assertEqual(rows[1]["grant_ids"], ["decl-second"])

    def test_query_engine_request_history(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-history"))
        self.harness.ingest_request(request_payload("req-history"))
        history = TemporalQueryEngine(self.harness.store).request_history("req-history")
        self.assertEqual(history["request"]["request_id"], "req-history")
        self.assertEqual(len(history["decisions"]), 1)
        self.assertGreaterEqual(len(history["audit_records"]), 1)

    def test_application_timeline_buckets_requests(self) -> None:
        self.harness.ingest_declaration(declaration_payload("decl-timeline", effective_until=timestamp(days=4)))
        self.harness.ingest_request(request_payload("req-day-1", requested_at=timestamp(days=1)))
        self.harness.ingest_request(request_payload("req-day-2", requested_at=timestamp(days=2)))
        rows = TemporalQueryEngine(self.harness.store).application_timeline(
            "dev.publisher", "app.market", parse_time(timestamp()), parse_time(timestamp(days=3)), timedelta(days=1)
        )
        self.assertEqual([row["total"] for row in rows], [0, 1, 1])

    def test_denial_clusters_groups_primary_reason(self) -> None:
        self.harness.ingest_request(request_payload("req-deny-1", capability="camera.capture"))
        self.harness.ingest_request(request_payload("req-deny-2", capability="camera.capture", region="US"))
        clusters = TemporalQueryEngine(self.harness.store).denial_clusters()
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0]["count"], 2)
        self.assertEqual(clusters[0]["primary_reason"], "no_active_declaration")


if __name__ == "__main__":
    unittest.main()
