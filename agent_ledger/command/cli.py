from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable

from ..audit.export import AuditExporter
from ..audit.report import ComplianceReport
from ..declarations.catalog import DeclarationCatalog
from ..declarations.parser import DeclarationParser
from ..errors import LedgerError, ValidationError
from ..ingest.processor import LedgerService
from ..ingest.reconcile import Reconciler
from ..policy.matrix import PolicyMatrix
from ..policy.simulator import PolicySimulator
from ..signatures.envelope import LocalKeyring
from ..temporal.index import TemporalDeclarationIndex
from ..temporal.query import TemporalQueryEngine
from ..temporal.store import LedgerStore
from ..util import parse_time, utc_now
from .io import dump_json, load_json, load_json_lines, require_array, require_object


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-ledger", description="Local temporal authorization ledger for cross-application agent calls")
    parser.add_argument("--db", default="ledger.sqlite3", help="SQLite ledger path")
    parser.add_argument("--key-id", default=os.environ.get("AGENT_LEDGER_KEY_ID", "developer-local"))
    parser.add_argument("--secret", default=os.environ.get("AGENT_LEDGER_SECRET", "local-synthetic-signing-secret-2026"))
    parser.add_argument("--compact", action="store_true", help="emit compact JSON")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init", help="initialize a ledger")
    init.set_defaults(handler=cmd_init)

    sign = subparsers.add_parser("sign", help="create a locally verifiable declaration envelope")
    sign.add_argument("input")
    sign.add_argument("--output")
    sign.set_defaults(handler=cmd_sign)

    ingest_declaration = subparsers.add_parser("ingest-declaration", help="verify and ingest a signed declaration")
    ingest_declaration.add_argument("input")
    ingest_declaration.add_argument("--event-id")
    ingest_declaration.add_argument("--received-at")
    ingest_declaration.set_defaults(handler=cmd_ingest_declaration)

    ingest_request = subparsers.add_parser("ingest-request", help="ingest and evaluate a call request")
    ingest_request.add_argument("input")
    ingest_request.add_argument("--event-id")
    ingest_request.add_argument("--received-at")
    ingest_request.set_defaults(handler=cmd_ingest_request)

    batch = subparsers.add_parser("batch", help="evaluate or ingest request batches")
    batch.add_argument("input")
    batch.add_argument("--json-lines", action="store_true")
    batch.add_argument("--ingest", action="store_true")
    batch.add_argument("--atomic", action="store_true")
    batch.set_defaults(handler=cmd_batch)

    reconcile = subparsers.add_parser("reconcile", help="recompute decisions affected by late declarations")
    reconcile.add_argument("--limit", type=int, default=100)
    reconcile.add_argument("--all", action="store_true")
    reconcile.set_defaults(handler=cmd_reconcile)

    explain = subparsers.add_parser("explain", help="explain current or historical authorization")
    explain.add_argument("request_id")
    explain.add_argument("--at")
    explain.set_defaults(handler=cmd_explain)

    history = subparsers.add_parser("history", help="show decision and audit history for a request")
    history.add_argument("request_id")
    history.set_defaults(handler=cmd_history)

    diff = subparsers.add_parser("diff", help="compare authorization at two policy times")
    diff.add_argument("request_id")
    diff.add_argument("first")
    diff.add_argument("second")
    diff.set_defaults(handler=cmd_diff)

    matrix = subparsers.add_parser("matrix", help="aggregate request decisions by dimensions")
    matrix.add_argument("input")
    matrix.add_argument("--dimensions", default="application_id,capability")
    matrix.set_defaults(handler=cmd_matrix)

    coverage = subparsers.add_parser("coverage", help="show declaration coverage intervals")
    coverage.add_argument("developer_id")
    coverage.add_argument("application_id")
    coverage.add_argument("agent_identity")
    coverage.add_argument("capability")
    coverage.add_argument("region")
    coverage.add_argument("version")
    coverage.add_argument("start")
    coverage.add_argument("end")
    coverage.set_defaults(handler=cmd_coverage)

    timeline = subparsers.add_parser("timeline", help="aggregate an application request timeline")
    timeline.add_argument("developer_id")
    timeline.add_argument("application_id")
    timeline.add_argument("start")
    timeline.add_argument("end")
    timeline.add_argument("--bucket-hours", type=int, default=24)
    timeline.set_defaults(handler=cmd_timeline)

    report = subparsers.add_parser("report", help="produce compliance findings")
    report.add_argument("--since")
    report.set_defaults(handler=cmd_report)

    export = subparsers.add_parser("export", help="export audit data")
    export.add_argument("output")
    export.add_argument("--format", choices=("json", "csv"), default="json")
    export.set_defaults(handler=cmd_export)

    catalog = subparsers.add_parser("catalog", help="inspect declaration inventory and conflicts")
    catalog.add_argument("--include-overlaps", action="store_true")
    catalog.set_defaults(handler=cmd_catalog)

    simulate = subparsers.add_parser("simulate", help="preview authorization impact without mutating the ledger")
    simulate.add_argument("input", help="JSON object with proposals and optional remove_ids")
    simulate.add_argument("--since")
    simulate.add_argument("--until")
    simulate.add_argument("--blast-radius", action="store_true")
    simulate.set_defaults(handler=cmd_simulate)

    suggest = subparsers.add_parser("suggest-scopes", help="summarize uncovered requests for human policy review")
    suggest.add_argument("--since")
    suggest.add_argument("--until")
    suggest.add_argument("--minimum-occurrences", type=int, default=1)
    suggest.set_defaults(handler=cmd_suggest_scopes)

    status = subparsers.add_parser("status", help="show ledger counts and late-event queue")
    status.set_defaults(handler=cmd_status)

    demo = subparsers.add_parser("demo", help="run the bundled synthetic acceptance scenario")
    demo.add_argument("fixture")
    demo.add_argument("--reset", action="store_true")
    demo.set_defaults(handler=cmd_demo)
    return parser


def context(args: argparse.Namespace) -> tuple[LedgerStore, LocalKeyring, LedgerService]:
    store = LedgerStore(args.db)
    keyring = LocalKeyring({args.key_id: args.secret})
    return store, keyring, LedgerService(store, keyring)


def cmd_init(args: argparse.Namespace) -> dict[str, Any]:
    store, keyring, _ = context(args)
    return {"db": str(Path(args.db)), "counts": store.counts(), "key_id": args.key_id, "key_fingerprint": keyring.fingerprint(args.key_id)}


def cmd_sign(args: argparse.Namespace) -> dict[str, Any]:
    _, keyring, _ = context(args)
    payload = require_object(load_json(args.input), "declaration")
    parser = DeclarationParser()
    declaration = parser.parse(payload)
    envelope = keyring.sign(args.key_id, declaration.as_payload(), signed_at=declaration.issued_at)
    result = envelope.as_dict()
    if args.output:
        dump_json(result, output=args.output, pretty=not args.compact)
        return {"output": args.output, "declaration_id": declaration.declaration_id}
    return result


def cmd_ingest_declaration(args: argparse.Namespace) -> dict[str, Any]:
    _, _, service = context(args)
    envelope = require_object(load_json(args.input), "signed declaration")
    received_at = None if args.received_at is None else parse_time(args.received_at, "received_at")
    return service.ingest_signed_declaration(envelope, event_id=args.event_id, received_at=received_at).as_dict()


def cmd_ingest_request(args: argparse.Namespace) -> dict[str, Any]:
    _, _, service = context(args)
    request = require_object(load_json(args.input), "request")
    received_at = None if args.received_at is None else parse_time(args.received_at, "received_at")
    return service.ingest_request(request, event_id=args.event_id, received_at=received_at).as_dict()


def cmd_batch(args: argparse.Namespace) -> dict[str, Any]:
    _, _, service = context(args)
    values = load_json_lines(args.input) if args.json_lines else require_array(load_json(args.input), "batch")
    if args.ingest:
        return service.ingest_batch_requests(values, atomic=args.atomic)
    return service.batch_evaluate(values).as_dict()


def cmd_reconcile(args: argparse.Namespace) -> dict[str, Any]:
    store, _, _ = context(args)
    reconciler = Reconciler(store)
    return (reconciler.rebuild_all() if args.all else reconciler.run(args.limit)).as_dict()


def cmd_explain(args: argparse.Namespace) -> dict[str, Any]:
    store, _, _ = context(args)
    point = None if args.at is None else parse_time(args.at, "at")
    return TemporalQueryEngine(store).decision_at(args.request_id, point)


def cmd_history(args: argparse.Namespace) -> dict[str, Any]:
    store, _, _ = context(args)
    return TemporalQueryEngine(store).request_history(args.request_id)


def cmd_diff(args: argparse.Namespace) -> dict[str, Any]:
    store, _, _ = context(args)
    return TemporalQueryEngine(store).decision_diff(args.request_id, parse_time(args.first), parse_time(args.second))


def cmd_matrix(args: argparse.Namespace) -> dict[str, Any]:
    store, _, service = context(args)
    values = require_array(load_json(args.input), "matrix requests")
    requests = [service.parser.parse_request(require_object(value, "request")) for value in values]
    dimensions = tuple(item.strip() for item in args.dimensions.split(",") if item.strip())
    cells = PolicyMatrix(service.evaluator, store).evaluate(requests, dimensions)
    return {"dimensions": list(dimensions), "cells": [item.as_dict(dimensions) for item in cells]}


def cmd_coverage(args: argparse.Namespace) -> dict[str, Any]:
    store, _, _ = context(args)
    rows = TemporalQueryEngine(store).declaration_coverage(
        args.developer_id, args.application_id, args.agent_identity, args.capability, args.region, args.version,
        parse_time(args.start), parse_time(args.end),
    )
    return {"intervals": rows}


def cmd_timeline(args: argparse.Namespace) -> dict[str, Any]:
    store, _, _ = context(args)
    rows = TemporalQueryEngine(store).application_timeline(
        args.developer_id, args.application_id, parse_time(args.start), parse_time(args.end), timedelta(hours=args.bucket_hours)
    )
    return {"buckets": rows}


def cmd_report(args: argparse.Namespace) -> dict[str, Any]:
    store, _, _ = context(args)
    since = None if args.since is None else parse_time(args.since, "since")
    return ComplianceReport(store).generate(since)


def cmd_export(args: argparse.Namespace) -> dict[str, Any]:
    store, _, _ = context(args)
    exporter = AuditExporter(store)
    return exporter.export_json(args.output) if args.format == "json" else exporter.export_decisions_csv(args.output)


def cmd_catalog(args: argparse.Namespace) -> dict[str, Any]:
    store, _, _ = context(args)
    index = TemporalDeclarationIndex.from_store(store)
    catalog = DeclarationCatalog(index.all())
    result = {"inventory": catalog.inventory(), "inheritance": catalog.inheritance_graph()}
    if args.include_overlaps:
        result["overlaps"] = [item.as_dict() for item in catalog.find_overlaps()]
    return result


def cmd_status(args: argparse.Namespace) -> dict[str, Any]:
    store, _, _ = context(args)
    query = TemporalQueryEngine(store)
    return {"counts": store.counts(), "late_event_impact": query.late_event_impact()}


def cmd_simulate(args: argparse.Namespace) -> dict[str, Any]:
    store, _, _ = context(args)
    value = require_object(load_json(args.input), "simulation")
    proposals = require_array(value.get("proposals", []), "simulation.proposals")
    remove_ids = require_array(value.get("remove_ids", []), "simulation.remove_ids")
    since = None if args.since is None else parse_time(args.since, "since")
    until = None if args.until is None else parse_time(args.until, "until")
    simulator = PolicySimulator(store)
    if args.blast_radius:
        return simulator.blast_radius(proposals, remove_ids=remove_ids, since=since, until=until)
    return simulator.simulate(proposals, remove_ids=remove_ids, since=since, until=until).as_dict()


def cmd_suggest_scopes(args: argparse.Namespace) -> dict[str, Any]:
    store, _, _ = context(args)
    since = None if args.since is None else parse_time(args.since, "since")
    until = None if args.until is None else parse_time(args.until, "until")
    rows = PolicySimulator(store).suggest_scopes(since=since, until=until, minimum_occurrences=args.minimum_occurrences)
    return {"suggestions": rows, "count": len(rows)}


def cmd_demo(args: argparse.Namespace) -> dict[str, Any]:
    fixture = require_object(load_json(args.fixture), "demo fixture")
    db_path = Path(args.db)
    if args.reset and db_path.exists():
        db_path.unlink()
    store, keyring, service = context(args)
    declaration_results = []
    for payload in require_array(fixture.get("declarations", []), "declarations"):
        declaration = service.parser.parse(require_object(payload, "declaration"))
        envelope = keyring.sign(args.key_id, declaration.as_payload(), signed_at=declaration.issued_at)
        declaration_results.append(service.ingest_signed_declaration(envelope, received_at=utc_now()).as_dict())
    request_results = []
    for payload in require_array(fixture.get("requests", []), "requests"):
        request_results.append(service.ingest_request(require_object(payload, "request")).as_dict())
    reconciliation = Reconciler(store).run(10000).as_dict()
    report = ComplianceReport(store).generate()
    expected = fixture.get("expected_statuses", {})
    actual = {item["entity_id"]: item["decision"]["status"] for item in request_results if item.get("decision")}
    mismatches = {key: {"expected": value, "actual": actual.get(key)} for key, value in expected.items() if actual.get(key) != value}
    if mismatches:
        raise ValidationError("demo expectations failed", details={"mismatches": mismatches})
    return {
        "declarations": declaration_results,
        "requests": request_results,
        "reconciliation": reconciliation,
        "report_summary": {"status_counts": report["status_counts"], "finding_counts": report["finding_counts"]},
        "counts": store.counts(),
        "expectations_verified": len(expected),
    }


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = args.handler(args)
        dump_json(result, pretty=not args.compact)
        return 0
    except LedgerError as exc:
        dump_json({"error": exc.as_dict()}, pretty=not args.compact)
        return 2
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        dump_json({"error": {"code": "command_error", "message": str(exc), "details": {}}}, pretty=not args.compact)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
