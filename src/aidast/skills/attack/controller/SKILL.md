---
name: aidast-attack
description: Run one persistent Codex Attack Agent over Recon SQLite data, dynamically load vendored Claude-BugHunter hunt skills, preserve cross-vulnerability state, and pursue exploit chains before committing results.
---

# Role

You are the only Attack Agent for this scan. Keep one continuous session from
the first Recon read through the final chain search. Do not spawn another agent
and do not run another Codex process.

Read `config.json`, `scope.md`, and the configured database contract first. Use
only the exact scan, database, SQLite executable, and commit scripts supplied by
the parent. The Recon DB is the shared source of endpoints, parameters,
sessions, prior attempts, facts, findings, and chains.

# Codex port of Claude-BugHunter

The installed `$hunt-*` skills and `$chain` are vendored verbatim from
Claude-BugHunter. Claude slash commands are not executable here:

- replace `/hunt` with this controller and `$hunt-dispatch`;
- replace `invoke each skill via the Skill tool` with loading the named Codex
  skill (`$hunt-xss`, `$hunt-idor`, and so on);
- replace `/chain` with `$chain` immediately after a skill confirms a finding;
- translate Bash examples to the available shell without changing the probe.
  In PowerShell use `curl.exe`, never the `curl` alias.

Original command files and provenance are packaged under the controller's
configured vendor path. They are reference material; this workflow owns
execution.

# Persistent attack loop

## 1. Build the live attack state

Query all non-excluded endpoints, parameters, origins, technologies, and
available sessions for the scan. Query `attack_tasks`, `attack_facts`,
`attack_attempts`, `findings`, and `finding_chains` so a resumed run does not
repeat completed work.

Load `$hunt-dispatch` first. Apply its soft-404 baseline, fingerprint routing,
signal precedence, and de-duplication rules to the Recon rows. Do not ask the
operator mode questions: this project is always `mode=wapt box=blackbox`, with
authenticated sessions additionally available when Recon already captured
them.

Create a prioritized queue covering every relevant vendored `hunt-*` skill.
Signal-matched skills go first; general WAPT skills follow. Use waves of at most
eight loaded skill bodies so high-signal instructions remain salient. Continue
to later waves until every applicable skill is completed, explicitly deferred
for a missing prerequisite, or superseded by a stronger skill.

## 2. Execute without losing context

For each queue item:

1. Load its exact `$hunt-*` skill and follow its probes, bypasses, validation,
   and composition guidance.
2. Reuse the same login sessions, cookies, CSRF state, discovered identifiers,
   GraphQL types, API versions, and application model accumulated earlier.
3. Before a request, query `attack_attempts` by a stable fingerprint made from
   method, normalized URL, identity/role, and payload variant. Skip exact
   duplicates unless an earlier result explicitly requires confirmation.
4. Record each useful negative or positive attempt through the configured
   attempt commit script. Store reusable discoveries through the fact commit
   script. Never put live credentials in facts; credentials remain in
   `sessions.auth_state`.
5. Reprioritize the remaining queue whenever a response creates a stronger
   lead. Examples: an ID feeds GraphQL and authz tests; an open redirect moves
   OAuth forward; XSS moves ATO/admin-view tests forward; SSRF moves cloud and
   internal-service skills forward.

Use a skill's own confirmation criteria before creating a finding. A status
code alone is never sufficient evidence. Capture the minimum complete HTTP
request/response set needed for later independent validation.

## 3. Commit findings generically

For each confirmed vulnerability, create a UTF-8 JSON payload matching the
database contract and commit it atomically with the configured generic finding
script. `vuln_type`, CWE, severity, endpoint, and evidence must come from the
active skill and observed behavior; never default all findings to IDOR.

Re-query the inserted finding before continuing. The completion envelope may
contain IDs only, never bodies or credentials.

## 4. Chain immediately

After every committed finding A:

1. Load `$chain` and apply its A→B→C signal table.
2. Also read the active skill's `Chains & Compositions` or equivalent section.
3. Promote matching B tasks to the front of the same queue and pass all facts
   learned from A. Do not create a separate chaining agent or reset context.
4. Test B and C using their own `$hunt-*` skills. Each independently confirmed
   bug is committed as its own finding.
5. When two or more committed findings form one demonstrated exploit path,
   commit their ordered relationship with the configured chain script.

Continue ordinary hunting after a chain branch closes. A failed B candidate is
an attempt, not proof that unrelated skill families are exhausted.

## 5. Complete

Re-query all findings created during this Attack run and all committed chains.
Return only:

```json
{
  "stage": "ATTACK",
  "status": "COMPLETED",
  "scan_id": "the configured scan ID",
  "db_path": "the exact configured absolute DB path",
  "finding_ids": ["IDs committed by this run"],
  "validation_id": null,
  "summary": "short count summary without secrets"
}
```

An empty finding list is valid only after the applicable queue has been
processed. If a required DB commit or configured tool fails, return `FAILED`;
never disguise infrastructure failure as zero findings.

