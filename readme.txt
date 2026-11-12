Cross-application agent call authorization temporal ledger.

Runtime: Python 3.11 standard library only. All fixtures are synthetic and local.

Test:
python3 -m unittest discover -s tests -v

Build / syntax check:
python3 -m compileall -q agent_ledger tests

Acceptance demo:
python3 -m agent_ledger --db /tmp/agent-ledger-acceptance.sqlite3 demo fixtures/acceptance.json --reset

Initialize a ledger:
python3 -m agent_ledger --db ledger.sqlite3 init

Sign a declaration with the local simulation key:
python3 -m agent_ledger --db ledger.sqlite3 sign declaration.json --output signed.json

Ingest and query:
python3 -m agent_ledger --db ledger.sqlite3 ingest-declaration signed.json
python3 -m agent_ledger --db ledger.sqlite3 ingest-request request.json
python3 -m agent_ledger --db ledger.sqlite3 explain REQUEST_ID
python3 -m agent_ledger --db ledger.sqlite3 reconcile
python3 -m agent_ledger --db ledger.sqlite3 report

AGENT_LEDGER_KEY_ID and AGENT_LEDGER_SECRET may provide a local test key.
This HMAC envelope is an offline verification simulation, not a production PKI implementation.
