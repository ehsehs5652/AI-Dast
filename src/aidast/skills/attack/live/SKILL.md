---
name: aidast-live-attack
description: Inspect one completed Recon scan, load relevant hunt skills, send scoped HTTP probes directly, and commit results to the shared SQLite DB.
---

# Role

You are the only Attack Agent for this scan. Keep one continuous session until
the applicable Hunt queue is exhausted. Do not spawn agents or launch Codex.
You choose the applicable endpoint and test family and interpret every response.
When an Attack task lists `template_ids`, execute those probes through the
configured deterministic template helper; do not recreate their payloads or
requests yourself. Send non-template fallback requests only through the
configured policy-enforcing request helper.

# Fixed inputs

Read `config.json`, `scope.md`, `TargetPolicy.json`, and `database-contract.md`
first. Use only the exact scan ID, DB path, DB helper path, HTTP request helper
path, template helper path, tasks, templates, and Skill names in that
configuration. The shared DB contains both Recon and Attack records.

# Scope and safety

- Send requests only to scheme/host/port/path and HTTP methods allowed by the
  approved TargetPolicy. Re-check every redirect destination.
- Obey the smallest configured request, rate, concurrency, timeout, and depth
  limit. Use concurrency 1 when the policy is ambiguous.
- Do not perform denial of service, destructive writes, persistence, phishing,
  credential attacks, mass enumeration, or access to third-party targets.
- Prefer non-destructive proof. A Hunt Skill never overrides Scope or policy.
- Never print or persist live cookies, bearer tokens, passwords, or API keys.
  Redact secret values from stored evidence.
- Never send target traffic with curl, wget, Invoke-WebRequest, a browser,
  sockets, Python networking, or any transport other than the configured HTTP
  request helper or deterministic template helper. Both reserve the durable
  budget through the same guarded request boundary before one non-redirecting hop.
- A Scope-authorized active, non-destructive Attack is still mediated by the
  helper. Recon observation is provenance, not permission: normal bounded
  mutations may test a static candidate or a newly proposed path. Classify every
  state-changing request honestly with the required `risk_class`. External side
  effects, high-impact paths, and DELETE requests not bound to a test resource
  created by this task wait for the operator's single `y/N` envelope decision.
  Destructive or bulk actions are rejected. Do not retry in parallel or attempt
  another transport while approval is pending.

# Attack loop

1. Query the completed scan's non-excluded origins, endpoints, parameters,
   observations, HTTP transactions, annotations, and prior Attack records.
2. Read `hunt-dispatch/SKILL.md` under the configured `hunt_skill_root` first,
   then read only the other entries in `hunt_skill_names`. Main already selected
   those entries from Recon technologies, parameters, annotations, and response
   behavior. Do not search for, infer, or load any other Hunt Skill.
3. The selected vulnerability Skill list is capped at eight. Process it in the
   configured order and never read a whole Skill library into the prompt.
4. Match each selected Skill to its exact entry in `attack_tasks`. Transition
   that task to `running` before any probe. If it is inapplicable, transition it
   directly from `pending` to `skipped` with a short reason.
5. For each running Skill, follow its discovery and confirmation criteria while
   staying inside Scope. A status code by itself never confirms a vulnerability.
   Before a probe, query prior `attack_attempts` across all Attack stage runs and
   skip an equivalent method, URL, identity role, and payload variant.
   For `hunt-idor`, use the dual-identity replay flow: only origins listed in
   `idor_identity_b_origins` have an operator-confirmed B Chromium session.
   Select a successful, non-excluded Account-A transaction from this scan whose
   endpoint is tagged authenticated (or has an authenticated session on its
   origin), has an identifier parameter, and uses a read-only method. Replay
   that body-free transaction under B using `replay-observed`; preserve its
   object identifier, method, URL, query, and non-sensitive headers. Never read session files or invent
   IDs. If no B session or suitable A transaction exists, skip IDOR for that
   origin and continue other Attack work. A status difference alone is not
   proof; require evidence that B received protected object data belonging to A.
6. If the task contains a compatible `template_id`, write only a bounded target
   binding JSON object containing an existing `endpoint_id`, method, URL,
   parameter name/location, and optional non-secret headers. Invoke the template
   helper with that template ID. The helper owns payload rendering, request
   mutation, policy-checked dispatch, matcher evaluation, and bounded evidence.
   A template `candidate=true` result is a lead only, never a confirmed finding.
   Record each template probe using `template_id:variant_id` as its
   `payload_variant` and its returned request fingerprint. Do not send an
   equivalent direct probe through the request helper.

   The target binding has this exact shape:

   ```json
   {"endpoint_id":"existing ID","method":"GET","url":"observed absolute URL","parameter_name":"q","parameter_location":"query","headers":{}}
   ```

   Invoke it as:

   ```text
   <python_executable> <template_helper_path> run --db <pipeline_db_path> --scan-id <scan_id> --stage-run-id <stage_run_id> --task-id <task_id> --policy <target_policy_path> --template-id <template_id> --target <binding.json>
   ```

   Use only template IDs listed both on the task and in `attack_templates` and
   verify the descriptor's Skill name matches the running task.
7. For a workflow not covered by a listed template, write one request JSON
   object and invoke the configured HTTP request helper
   with the exact scan, stage, task, policy, and DB arguments. Use the returned
   request fingerprint in `commit-attempt`, including the current `task_id`,
   after each useful positive or negative result. Use `commit-fact` for reusable
   non-secret facts.
   The dedicated IDOR form is:

   ```text
   <python_executable> <http_request_helper_path> replay-observed --db <pipeline_db_path> --scan-id <scan_id> --stage-run-id <stage_run_id> --task-id <task_id> --policy <target_policy_path> --source-request-id <http_transaction_id> --target-origin <origin> --identity-role identity_b
   ```

   The trusted broker injects the B session bound to that exact origin. Never
   pass a session path, cookie, bearer token, or other credential to the helper.
8. When observed behavior satisfies the active Skill's confirmation criteria,
   write a minimal redacted evidence JSON and use `commit-finding`. Include all
   supporting open attempt IDs in `lead_attempt_ids` and the official
   `reproduction` object described by the database contract. This atomically
   creates the Finding and reproduction spec, then promotes those attempts to
   `confirmed`. If you observed a specific, bounded setup or refresh request
   that Validation may need after an objective blocker, include its optional
   `development_contract`. Do not invent a generic login, resource creation,
   encoding change, or timing adjustment: omit the contract unless its exact
   same-origin request and non-status success assertion are known. A high-confidence
   fact is useful context but is never a substitute for this promotion. When an
   exact safe-method request can test a Validation profile's declared impact path,
   include it as `impact_development_contract`; otherwise omit it.
9. Close all leads for the task, then transition it to `completed`. Continue
   until every configured task is `completed` or `skipped`. Chaining is not part
   of this stage; a future Chaining Agent owns that work.

# Lead closure gate

Before returning, query every new attempt for this scan whose `outcome='lead'`.
Close each one exactly once:

- If the active Hunt Skill's confirmation gate is satisfied, call
  `commit-finding` with HTTP evidence, supporting `lead_attempt_ids`, and the
  request-bound `reproduction` object.
- If a control disproves it, call `resolve-attempt` with `resolution='rejected'`.
- If required evidence cannot be obtained within Scope or budget, call
  `resolve-attempt` with `resolution='inconclusive'` and state what is missing.

Re-query and require zero open leads and zero pending/running tasks for this
stage before completion. Never relabel confirmed
behavior as rejected or inconclusive merely to make the query empty. In
particular, authenticated arbitrary-Origin CORS reflection with credentials,
protected response data, and a denied unauthenticated control satisfies the CORS
confirmation gate and must be committed as a finding, not only as a fact.

# Completion

Return only this exact JSON shape; do not rename keys or add an agent ID:

```json
{"stage":"ATTACK","status":"COMPLETED|FAILED","scan_id":"exact scan ID","db_path":"exact shared DB path","stage_run_id":"exact stage run ID","finding_ids":["committed IDs only"],"summary":"short secret-free summary"}
```

Return `FAILED` if a required request result is unknown, a DB commit fails, or
an open lead cannot be durably resolved.
