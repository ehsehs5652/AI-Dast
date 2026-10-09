# AI-DAST-ALL Recon/Attack Source Reconciliation

The merge uses the nested `AI-DAST-ALL` working tree as the functional source
for Recon and Attack while retaining stricter behavior already present on the
current branch. Source hashes are recorded in
`AI_DAST_ALL_SOURCE_MANIFEST.json`.

| Source file | Behavioral delta | Decision | Current replacement | Required regression test |
|---|---|---|---|---|
| `recon/annotations.py` | Uses batches of 50, accepts partial model coverage, and continues with successfully tagged observations | Reject partial continuation; progress messages may be adopted only without changing completeness | Exact supplied-observation coverage and downstream annotation gate | Missing annotations prevent Attack handoff |
| `recon/executor.py` | Removes injected request headers | Reject | Current guarded propagation of approved Intigriti headers | Required headers reach probe and discovery transports |
| `recon/policy.py` | Uses older URL/scheme/port validation | Reject | Current URL provenance and exact scheme/port constraints | Non-URL targets cannot broaden HTTPS/443 |
| `recon/tools/endpoint_discovery.py` | Omits current authentication provenance integration | Reject | Current passive, secret-free auth endpoint provenance | Stored auth provenance contains no credential material |
| `recon/tools/playwright_driver.py` | Predates current authenticated endpoint and browser boundary changes | Reject wholesale replacement | Current route, session, and endpoint provenance guards | Browser traffic remains policy-bound |
| `cli.py` | Hard-codes `result/`, removes updater/runtime Scope login/Intigriti options, and continues after partial tagging or Recon errors | Reject | Current `AIDAST_RESULT_ROOT`, Auth/Scope CLI, tagging completeness, and completed-only handoff | CLI defaults and downstream gates stay unchanged |
| `attack/store.py` | Accepts `completed_with_errors` Recon and adds durable attempt/revocation methods | Split: reject relaxed scan acceptance; accept attempt and revocation methods | Current completed-only source verification plus imported durable methods | Incomplete scans rejected; attempt/revocation state persists |
| `attack/db_cli.py` | Uses schema v9 reproduction shape without impact-development fields | Reject | Current schema v10 runtime, development, and impact-development contract validation | v10 hashes persist and invalid widening rolls back |
| `pipeline/live_schema.py` | Sets user version 9 and lacks protocol/impact tables and columns | Reject | Current additive schema v10 | `PRAGMA user_version=10` and protocol suites pass |
| `reporting/case_runtime.py` | Traverses every nested key ending in `evidence_ids` | Reject | Current explicit Validation evidence namespaces | Nested Attack evidence is ignored; foreign Validation evidence is rejected |
| `attack/ed25519_authorization.py` and related new Attack modules | Adds local signed authorization, intent, policy executor, session, launcher, and workflow capabilities | Accept after TDD and current-contract adaptation | New modules under current package; no automatic CLI trust | Dedicated tests for every public execution boundary |

No entire Recon file is copied. A Recon production change requires a focused
test demonstrating a safe capability that is absent from the current branch.
