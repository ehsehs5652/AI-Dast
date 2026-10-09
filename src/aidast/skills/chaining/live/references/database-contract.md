# Chaining database and helper contract

Use the absolute paths and identifiers from `config.json`. Invoke helpers with
`python_executable`; never import or copy their implementation.

## Read boundary

Read the SQLite database only for the configured `scan_id`. Eligible findings
have status `unreviewed` or `confirmed` and are linked to an `attack_attempts`
row whose outcome is `confirmed`. Do not treat a `lead` as a proven finding.

## Task lifecycle

Each `chain_tasks` item is an `attack_tasks` row whose `skill_name` is `chain`.
Use `db_helper_path transition-task` to change it from `pending` to `running`,
then to `completed` or `skipped`. Use a non-empty reason when skipping. Do not
modify rows with SQL.

## Candidate lifecycle

Write a JSON payload file in the temporary working directory and run:

```text
<python> <chaining_db_helper_path> commit-candidate --db <pipeline_db_path> --scan-id <scan_id> --stage-run-id <stage_run_id> --payload <payload.json>
```

The payload contains `task_id`, `source_finding_id`, `title`, `hypothesis`,
optional `terminal_impact` and `confidence`, two to four ordered `nodes`, and one
to three `edges`. Node zero must reference the source finding. A node may omit
`finding_id` only when it describes an expected, not-yet-proven step. For a
standalone finding, use the relevant staged Hunt guidance to name a specific
expected step and edge; never fabricate evidence that the step already exists.

Resolve an unsupported hypothesis with `resolve-candidate`. Its payload contains
`task_id`, `candidate_id`, `resolution` (`rejected` or `inconclusive`), and a
specific `reason`.

An expected node without an Attack-proven finding must end `inconclusive`, with
the missing evidence or prerequisite stated in `reason`.

## Additional probes

Use `http_request_helper_path` exactly as documented by the staged Hunt Skills.
It enforces Scope, policy, rate, and the shared Attack/Chaining request budget.
Record the result with `db_helper_path commit-attempt`, using the current chain
task ID and `skill_name` equal to `chain`. Any finding derived from it must be
committed with the same task ID. Resolve all `lead` attempts before closing the
task. Never repeat a request whose outcome is unknown.

## Complete flow execution

Use this workflow only when every candidate node references a distinct or
intentionally repeated Attack-proven finding. Never execute an expected node
that has no `finding_id`.

1. Run `begin-execution` with a payload containing `task_id` and `candidate_id`.
2. Replay every node in order with one fresh HTTP request. Each request must be
   committed as a `lead` attempt with `skill_name: chain`.
3. Run `record-execution-step` after each request. Its payload contains
   `task_id`, `execution_id`, zero-based `position`, the node `finding_id`, the
   helper-returned `request_id`, matching `attempt_id`, and an evidence summary.
4. Run `finish-execution`. Use `succeeded` only if every edge transferred a
   captured value and the final request passed a terminal impact assertion.
   Otherwise use `rejected` or `inconclusive` and give a concrete reason.

The HTTP request payload optionally supports:

- `captures`: bounded `json_body` entries with `name` and `path`, or `header`
  entries with `name` and `header`.
- `bindings`: entries with `name`, `source_request_id`, `capture_name`, and the
  exact captured scalar `value`. For a replayable demonstrated chain, also set
  `target_kind` to `path_parameter`, `query_parameter`, `request_header`, or
  `json_body`, and set `target_path` to the field path. The helper checks the
  value hash against the source response, verifies that the outgoing request
  uses it, and stores the source/target locations without storing the value.
- `assertions`: `status_equals`, `json_equals`, `header_equals`, or
  `body_contains` entries. Mark a final non-status assertion with
  `terminal: true` only when it directly proves the declared impact.

For example, capture one JSON identifier:

```json
{"captures":[{"name":"account_id","source":"json_body","path":["account_id"]}]}
```

Then consume it in the next request and assert the final impact:

```json
{
  "bindings":[{
    "name":"object_id",
    "source_request_id":"HTTP_REQUEST_ID",
    "capture_name":"account_id",
    "value":"EXACT_HELPER_RETURNED_VALUE",
    "target_kind":"path_parameter",
    "target_path":["account_id"]
  }],
  "assertions":[{
    "name":"private_record_disclosed",
    "kind":"json_equals",
    "path":["private"],
    "expected":true,
    "terminal":true
  }]
}
```

`finish-execution` with `succeeded` also requires chain metadata: `title`,
`description`, `combined_severity`, and optional node-aligned `roles`. It creates
the `proposed` chain, resolves replay attempts against their existing findings,
stores step evidence, and returns the new `chain_id`. Include every started
execution in `execution_ids`, including rejected or inconclusive executions.

The legacy `commit-chain` command does not prove a complete flow and must not be
used by this Agent. Before returning, query the configured stage rows and include
exactly the new candidate, chain, and execution IDs. Every task must be completed
or skipped, every candidate and execution terminal, every lead resolved, and
every HTTP request terminal.
