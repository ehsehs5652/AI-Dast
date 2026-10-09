"""Small standalone SQLite CLI used by the native Attack Agent.

The agent owns HTTP execution and result interpretation.  This helper only
provides read-only Recon queries and parameterized writes into the shared DB;
it deliberately contains no vulnerability or request logic.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from contextlib import closing
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import uuid4


MAX_BODY_CHARS = 10_000
SENSITIVE_HEADERS = {
    "authorization", "cookie", "proxy-authorization", "set-cookie", "x-api-key"
}


def _payload(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("payload must be one JSON object")
    return value


def _text(value: object, *, required: bool = False, maximum: int = 100_000) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str) or len(value) > maximum or (required and not value.strip()):
        raise ValueError("invalid text field")
    return value


def _body(value: object) -> str:
    text = _text(value, maximum=1_000_000)
    return text if len(text) <= MAX_BODY_CHARS else text[:MAX_BODY_CHARS] + "\n... (truncated)"


def _headers(value: object) -> str:
    text = _text(value, maximum=20_000)
    lines = []
    for line in text.splitlines():
        name, separator, remainder = line.partition(":")
        normalized = name.strip().casefold().replace("_", "-")
        if separator and (
            normalized in SENSITIVE_HEADERS
            or any(part in normalized for part in ("token", "secret", "api-key", "apikey"))
        ):
            lines.append(f"{name}: [REDACTED]")
        else:
            lines.append(line)
    return "\n".join(lines)


def _url(value: object, *, required: bool = False) -> str:
    raw = _text(value, required=required, maximum=8192)
    if not raw:
        return raw
    parsed = urlsplit(raw)
    query = urlencode([
        (name, "[REDACTED]") for name, _ in parse_qsl(parsed.query, keep_blank_values=True)
    ])
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


def _completed_scan(conn: sqlite3.Connection, scan_id: str) -> None:
    row = conn.execute(
        "SELECT status,finished_at FROM scans WHERE scan_id=?", (scan_id,)
    ).fetchone()
    if row is None or str(row[0]).casefold() not in {"completed", "completed_with_errors"} or not row[1]:
        raise ValueError("writes require a completed Recon scan")


def _endpoint(conn: sqlite3.Connection, scan_id: str, endpoint_id: str | None) -> None:
    if not endpoint_id:
        return
    row = conn.execute(
        """SELECT 1 FROM endpoints e JOIN origins o ON o.origin_id=e.origin_id
           JOIN assets a ON a.asset_id=o.asset_id
           WHERE e.endpoint_id=? AND a.scan_id=? AND e.is_excluded=0""",
        (endpoint_id, scan_id),
    ).fetchone()
    if row is None:
        raise ValueError("endpoint does not belong to the completed scan")


def _running_task(
    conn: sqlite3.Connection, *, scan_id: str, task_id: str, skill_name: str | None = None
) -> None:
    row = conn.execute(
        """SELECT t.status,t.skill_name,s.status
           FROM attack_tasks t JOIN stage_runs s ON s.stage_run_id=t.stage_run_id
           WHERE t.task_id=? AND t.scan_id=?""",
        (task_id, scan_id),
    ).fetchone()
    if row is None or row[0] != "running" or row[2] != "running":
        raise ValueError("writes require a running Attack task")
    if skill_name is not None and row[1] != skill_name:
        raise ValueError("attempt skill_name does not match its Attack task")


def query(db_path: Path, sql: str) -> list[dict]:
    if not sql.strip():
        raise ValueError("query SQL is empty")
    if sql.lstrip().split(None, 1)[0].casefold() not in {"select", "with"}:
        raise ValueError("only SELECT queries are allowed")
    with closing(sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True)) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        cursor = conn.execute(sql)
        if cursor.description is None:
            raise ValueError("query must return rows")
        rows = [dict(row) for row in cursor.fetchmany(10_001)]
        if len(rows) > 10_000:
            raise ValueError("query result exceeds 10000 rows")
        return rows


def commit_attempt(db_path: Path, scan_id: str, payload_path: Path) -> dict:
    item = _payload(payload_path)
    endpoint_id = _text(item.get("endpoint_id")) or None
    skill_name = _text(item.get("skill_name"), required=True, maximum=128)
    fingerprint = _text(item.get("request_fingerprint"), required=True, maximum=512)
    task_id = _text(item.get("task_id"), required=True, maximum=256)
    attempt_id = _text(item.get("attempt_id"), maximum=256) or "attempt_" + uuid4().hex
    outcome = _text(item.get("outcome"), maximum=128) or "inconclusive"
    if outcome not in {"negative", "lead", "inconclusive"}:
        raise ValueError("attempt outcome must be negative, lead, or inconclusive")
    with closing(sqlite3.connect(db_path)) as conn, conn:
        conn.execute("PRAGMA foreign_keys=ON")
        _completed_scan(conn, scan_id)
        _endpoint(conn, scan_id, endpoint_id)
        _running_task(conn, scan_id=scan_id, task_id=task_id, skill_name=skill_name)
        cursor = conn.execute(
            """INSERT OR IGNORE INTO attack_attempts
               (attempt_id,scan_id,task_id,skill_name,endpoint_id,request_fingerprint,
                method,url,identity_role,payload_variant,response_status,response_signature,outcome)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                attempt_id, scan_id, task_id, skill_name, endpoint_id, fingerprint,
                _text(item.get("method"), maximum=16) or None,
                _url(item.get("url")) or None,
                _text(item.get("identity_role"), maximum=128) or "unauthenticated",
                _text(item.get("payload_variant"), maximum=512),
                item.get("response_status"),
                _text(item.get("response_signature"), maximum=512) or None,
                outcome,
            ),
        )
        committed = cursor.rowcount == 1
        if not committed:
            row = conn.execute(
                """SELECT attempt_id FROM attack_attempts
                   WHERE scan_id=? AND skill_name=? AND request_fingerprint=?
                     AND identity_role=? AND payload_variant=?""",
                (
                    scan_id, skill_name, fingerprint,
                    _text(item.get("identity_role"), maximum=128) or "unauthenticated",
                    _text(item.get("payload_variant"), maximum=512),
                ),
            ).fetchone()
            if row is None:
                raise ValueError("duplicate attempt could not be reconciled")
            attempt_id = row[0]
        return {"attempt_id": attempt_id, "committed": committed}


def transition_task(
    db_path: Path, scan_id: str, stage_run_id: str, task_id: str,
    status: str, reason: str | None = None,
) -> dict:
    transitions = {
        "pending": {"running", "skipped"},
        "running": {"completed", "failed"},
    }
    if status not in {"running", "completed", "skipped", "failed"}:
        raise ValueError("invalid Attack task status")
    if status == "failed" and not (reason or "").strip():
        raise ValueError("failed Attack tasks require a reason")
    with closing(sqlite3.connect(db_path)) as conn, conn:
        conn.execute("PRAGMA foreign_keys=ON")
        _completed_scan(conn, scan_id)
        row = conn.execute(
            """SELECT t.status,s.status FROM attack_tasks t
               JOIN stage_runs s ON s.stage_run_id=t.stage_run_id
               WHERE t.task_id=? AND t.scan_id=? AND t.stage_run_id=?""",
            (task_id, scan_id, stage_run_id),
        ).fetchone()
        if row is None or row[1] != "running" or status not in transitions.get(row[0], set()):
            raise ValueError("invalid or stale Attack task transition")
        if status == "completed":
            open_leads = conn.execute(
                "SELECT COUNT(*) FROM attack_attempts WHERE task_id=? AND outcome='lead'",
                (task_id,),
            ).fetchone()[0]
            if open_leads:
                raise ValueError("Attack task has unresolved leads")
        timestamp = "CURRENT_TIMESTAMP"
        conn.execute(
            f"""UPDATE attack_tasks SET status=?,error_message=?,
                started_at=CASE WHEN ?='running' THEN {timestamp} ELSE started_at END,
                finished_at=CASE WHEN ? IN ('completed','skipped','failed')
                                 THEN {timestamp} ELSE finished_at END
                WHERE task_id=?""",
            (status, reason, status, status, task_id),
        )
        conn.execute(
            """INSERT INTO audit_events
               (audit_event_id,scan_id,stage_run_id,task_id,event_type,details_json)
               VALUES (?,?,?,?,?,?)""",
            (
                "audit_" + uuid4().hex, scan_id, stage_run_id, task_id,
                f"task.{status}", json.dumps({"previous_status": row[0], "reason": reason}),
            ),
        )
        return {"task_id": task_id, "status": status}


def resolve_attempt(db_path: Path, scan_id: str, payload_path: Path) -> dict:
    """Close a non-confirmed lead; confirmed leads are closed by commit_finding."""
    item = _payload(payload_path)
    attempt_id = _text(item.get("attempt_id"), required=True, maximum=256)
    resolution = _text(item.get("resolution"), required=True, maximum=32).casefold()
    if resolution not in {"rejected", "inconclusive"}:
        raise ValueError("lead resolution must be rejected or inconclusive")
    reason = _text(item.get("reason"), required=True, maximum=2000)
    with closing(sqlite3.connect(db_path)) as conn, conn:
        conn.execute("PRAGMA foreign_keys=ON")
        _completed_scan(conn, scan_id)
        cursor = conn.execute(
            """UPDATE attack_attempts
               SET outcome=?,resolution_reason=?,resolved_at=CURRENT_TIMESTAMP
               WHERE attempt_id=? AND scan_id=? AND outcome='lead'
                 AND finding_id IS NULL AND resolved_at IS NULL""",
            (resolution, reason, attempt_id, scan_id),
        )
        if cursor.rowcount != 1:
            raise ValueError("attempt is not an open lead for this scan")
        return {"attempt_id": attempt_id, "resolution": resolution, "resolved": True}


def commit_fact(db_path: Path, scan_id: str, payload_path: Path) -> dict:
    item = _payload(payload_path)
    endpoint_id = _text(item.get("source_endpoint_id")) or None
    fact_id = _text(item.get("fact_id"), maximum=256) or "fact_" + uuid4().hex
    confidence = item.get("confidence", 1.0)
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
        raise ValueError("invalid fact confidence")
    with closing(sqlite3.connect(db_path)) as conn, conn:
        conn.execute("PRAGMA foreign_keys=ON")
        _completed_scan(conn, scan_id)
        _endpoint(conn, scan_id, endpoint_id)
        cursor = conn.execute(
            """INSERT OR IGNORE INTO attack_facts
               (fact_id,scan_id,fact_type,fact_key,fact_value,confidence,
                source_endpoint_id,source_finding_id) VALUES (?,?,?,?,?,?,?,?)""",
            (
                fact_id, scan_id,
                _text(item.get("fact_type"), required=True, maximum=128),
                _text(item.get("fact_key"), required=True, maximum=512),
                _text(item.get("fact_value"), maximum=8192) or None,
                float(confidence), endpoint_id,
                _text(item.get("source_finding_id"), maximum=256) or None,
            ),
        )
        return {"fact_id": fact_id, "committed": cursor.rowcount == 1}


def commit_finding(db_path: Path, scan_id: str, payload_path: Path) -> dict:
    item = _payload(payload_path)
    if item.get("scan_id") != scan_id:
        raise ValueError("finding scan_id mismatch")
    endpoint_id = _text(item.get("endpoint_id")) or None
    if endpoint_id is None:
        raise ValueError("a finding reproduction requires endpoint_id")
    severity = _text(item.get("severity"), required=True).upper()
    if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
        raise ValueError("invalid finding severity")
    evidence = item.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise ValueError("a finding requires HTTP evidence")
    lead_attempt_ids = item.get("lead_attempt_ids", [])
    if not isinstance(lead_attempt_ids, list) or any(
        not isinstance(value, str) or not value.strip() or len(value) > 256
        for value in lead_attempt_ids
    ):
        raise ValueError("lead_attempt_ids must be a list of attempt IDs")
    if len(lead_attempt_ids) != len(set(lead_attempt_ids)):
        raise ValueError("lead_attempt_ids contains duplicates")
    reproduction = item.get("reproduction")
    if not isinstance(reproduction, dict):
        raise ValueError("a finding requires one reproduction object")
    finding_id = _text(item.get("finding_id"), maximum=256) or "finding_" + uuid4().hex
    cvss = item.get("cvss_score")
    if cvss is not None and (isinstance(cvss, bool) or not isinstance(cvss, (int, float)) or not 0 <= cvss <= 10):
        raise ValueError("invalid CVSS score")
    with closing(sqlite3.connect(db_path)) as conn, conn:
        conn.execute("PRAGMA foreign_keys=ON")
        _completed_scan(conn, scan_id)
        _endpoint(conn, scan_id, endpoint_id)
        placeholders = ",".join("?" for _ in lead_attempt_ids) or "NULL"
        source_attempts = conn.execute(
            f"""SELECT attempt_id,task_id,skill_name,endpoint_id,request_fingerprint
            FROM attack_attempts WHERE scan_id=? AND outcome='lead' AND finding_id IS NULL
            AND attempt_id IN ({placeholders})""", (scan_id, *lead_attempt_ids),
        ).fetchall()
        if len(source_attempts) != len(lead_attempt_ids) or not source_attempts:
            raise ValueError("reproduction requires supporting open lead attempts")
        if any(row[3] != endpoint_id for row in source_attempts):
            raise ValueError("reproduction attempts must use the finding endpoint")
        skills = {row[2] for row in source_attempts}
        if len(skills) != 1:
            raise ValueError("reproduction attempts must have exactly one Hunt Skill")
        attack_skill_name = next(iter(skills))
        source_request_ids = reproduction.get("source_request_ids")
        if (not isinstance(source_request_ids, list) or not source_request_ids
                or any(not isinstance(value, str) or not value for value in source_request_ids)
                or len(source_request_ids) != len(set(source_request_ids))):
            raise ValueError("reproduction source_request_ids are invalid")
        request_placeholders = ",".join("?" for _ in source_request_ids)
        source_requests = conn.execute(
            f"""SELECT request_id,task_id,request_fingerprint,method,policy_sha256,status
            FROM attack_http_requests WHERE scan_id=? AND request_id IN ({request_placeholders})""",
            (scan_id, *source_request_ids),
        ).fetchall()
        pairs = {(row[1], row[4]) for row in source_attempts}
        method = _text(reproduction.get("method"), required=True, maximum=16).upper()
        policy_digests = {row[4] for row in source_requests}
        if (len(source_requests) != len(source_request_ids) or len(policy_digests) != 1
                or None in policy_digests or any(
                    (row[1], row[2]) not in pairs or row[3].upper() != method
                    or row[5] != "completed" for row in source_requests
                )):
            raise ValueError("reproduction requests do not match the supporting attempts")
        endpoint_template = _text(reproduction.get("endpoint_template"), required=True, maximum=8192)
        injection_location = _text(reproduction.get("injection_location"), required=True, maximum=16)
        if injection_location not in {"path", "query", "header", "cookie", "body"}:
            raise ValueError("invalid reproduction injection_location")
        parameter_name = _text(reproduction.get("parameter_name"), required=True, maximum=256)
        payload_template = reproduction.get("payload_template")
        roles = reproduction.get("required_identity_roles", [])
        if (not isinstance(roles, list) or any(not isinstance(role, str) or not role for role in roles)
                or len(roles) != len(set(roles))):
            raise ValueError("invalid reproduction identity roles")
        runtime_contract = reproduction.get("runtime_contract")
        development_contract = reproduction.get("development_contract")
        impact_development_contract = reproduction.get("impact_development_contract")
        runtime_contract_json = None
        runtime_contract_sha256 = None
        resolved_profile = None
        if (runtime_contract is not None or development_contract is not None
                or impact_development_contract is not None):
            from aidast.validation.profiles import SkillProfileResolver
            resolved_profile = SkillProfileResolver().resolve(attack_skill_name).profile
        if runtime_contract is not None:
            from aidast.validation.runtime_contract import validate_runtime_contract
            from aidast.validation.models import canonical_json, canonical_sha256
            from aidast.validation.runtime_semantics import validate_runtime_semantics
            validated_runtime = validate_runtime_contract(runtime_contract)
            runtime_kind = validated_runtime.model_dump(mode="json").get(
                "runtime_kind", "http",
            )
            if runtime_kind not in resolved_profile.runtime_kinds:
                raise ValueError(
                    "runtime contract is incompatible with the Validation profile"
                )
            validate_runtime_semantics(
                validated_runtime,
                resolved_profile,
            )
            runtime_contract = validated_runtime.model_dump(mode="json")
            runtime_contract_json = canonical_json(runtime_contract)
            runtime_contract_sha256 = canonical_sha256(runtime_contract)
        development_contract_json = None
        development_contract_sha256 = None
        if development_contract is not None:
            from aidast.validation.development import DevelopmentRuntimeContract
            from aidast.validation.models import canonical_json, canonical_sha256
            validated_development = DevelopmentRuntimeContract.model_validate(
                development_contract
            )
            allowed_actions = {
                (action.action_type, action.blocker_axis)
                for action in resolved_profile.allowed_development_actions
            }
            if any(
                (action.action_type, action.blocker_axis) not in allowed_actions
                for action in validated_development.actions
            ):
                raise ValueError("development contract exceeds the Validation profile")
            if any(
                role not in roles
                for action in validated_development.actions
                for role in action.credential_roles
            ):
                raise ValueError("development contract uses an undeclared identity role")
            development_contract = validated_development.model_dump(mode="json")
            development_contract_json = canonical_json(development_contract)
            development_contract_sha256 = canonical_sha256(development_contract)
        impact_development_contract_json = None
        impact_development_contract_sha256 = None
        if impact_development_contract is not None:
            from aidast.validation import ImpactDevelopmentRuntimeContract
            from aidast.validation.models import canonical_json, canonical_sha256
            validated_impact = ImpactDevelopmentRuntimeContract.model_validate(
                impact_development_contract
            )
            paths = {
                path.path_id: path for path in resolved_profile.impact_expansion_paths
                if path.execution_owner == "validation"
            }
            for action in validated_impact.actions:
                if action.path_id not in paths:
                    raise ValueError("impact development contract exceeds the Validation profile")
                if action.endpoint_template != endpoint_template or action.method != method:
                    raise ValueError("impact development contract widens the reproduction endpoint")
                if any(role not in roles for role in action.credential_roles):
                    raise ValueError("impact development contract uses an undeclared identity role")
            impact_development_contract = validated_impact.model_dump(mode="json")
            impact_development_contract_json = canonical_json(impact_development_contract)
            impact_development_contract_sha256 = canonical_sha256(impact_development_contract)
        from aidast.validation.integrity import canonical_reproduction_spec
        spec = canonical_reproduction_spec(
            finding_id=finding_id, attack_skill_name=attack_skill_name,
            endpoint_id=endpoint_id, method=method, endpoint_template=endpoint_template,
            injection_location=injection_location, parameter_name=parameter_name,
            payload_template=payload_template, required_identity_roles=roles,
            source_attempt_ids=lead_attempt_ids, source_request_ids=source_request_ids,
            source_policy_sha256=next(iter(policy_digests)),
        )
        conn.execute(
            """INSERT INTO findings
               (finding_id,scan_id,endpoint_id,vuln_type,severity,title,description,
                cvss_score,cvss_vector,cwe_id)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                finding_id, scan_id, endpoint_id,
                _text(item.get("vuln_type"), required=True, maximum=128), severity,
                _text(item.get("title"), required=True, maximum=200),
                _text(item.get("description"), maximum=20_000) or None,
                cvss, _text(item.get("cvss_vector"), maximum=256) or None,
                _text(item.get("cwe_id"), maximum=64) or None,
            ),
        )
        for raw in evidence:
            if not isinstance(raw, dict):
                raise ValueError("finding evidence must contain JSON objects")
            body = _body(raw.get("response_body"))
            request_id = "areq_" + uuid4().hex
            conn.execute(
                """INSERT INTO attack_requests
                   (request_id,finding_id,role,method,url,request_headers,request_body,
                    response_status,response_headers,response_body,response_time_ms)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    request_id, finding_id,
                    _text(raw.get("role"), maximum=128) or "unknown",
                    _text(raw.get("method"), maximum=16) or "GET",
                    _url(raw.get("url"), required=True),
                    _headers(raw.get("request_headers")) or None,
                    _body(raw.get("request_body")) or None,
                    raw.get("response_status"),
                    _headers(raw.get("response_headers")) or None,
                    body or None, raw.get("response_time_ms"),
                ),
            )
        for attempt_id in lead_attempt_ids:
            cursor = conn.execute(
                """UPDATE attack_attempts
                   SET outcome='confirmed',finding_id=?,resolution_reason=?,
                       resolved_at=CURRENT_TIMESTAMP
                   WHERE attempt_id=? AND scan_id=? AND outcome='lead'
                     AND finding_id IS NULL AND resolved_at IS NULL""",
                (finding_id, "promoted to finding", attempt_id, scan_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("finding references an attempt that is not an open lead")
        conn.execute(
            """INSERT INTO finding_reproduction_specs
            (finding_id,attack_skill_name,endpoint_id,method,endpoint_template,injection_location,
             parameter_name,payload_template_json,required_identity_roles_json,
             source_attempt_ids_json,source_request_ids_json,payload_structure_sha256,
             source_policy_sha256,runtime_contract_json,runtime_contract_sha256,
             development_contract_json,development_contract_sha256,
             impact_development_contract_json,impact_development_contract_sha256,spec_sha256)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (spec["finding_id"], spec["attack_skill_name"], spec["endpoint_id"], spec["method"],
             spec["endpoint_template"], spec["injection_location"], spec["parameter_name"],
             json.dumps(spec["payload_template"], ensure_ascii=False, sort_keys=True, separators=(",", ":")),
             json.dumps(spec["required_identity_roles"], ensure_ascii=False, separators=(",", ":")),
             json.dumps(spec["source_attempt_ids"], ensure_ascii=False, separators=(",", ":")),
             json.dumps(spec["source_request_ids"], ensure_ascii=False, separators=(",", ":")),
             spec["payload_structure_sha256"], spec["source_policy_sha256"],
             runtime_contract_json, runtime_contract_sha256,
             development_contract_json, development_contract_sha256,
             impact_development_contract_json, impact_development_contract_sha256,
             spec["spec_sha256"]),
        )
        return {
            "finding_id": finding_id,
            "evidence_count": len(evidence),
            "promoted_attempt_count": len(lead_attempt_ids),
            "reproduction_spec_sha256": spec["spec_sha256"],
        }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    read = sub.add_parser("query")
    read.add_argument("--db", type=Path, required=True)
    source = read.add_mutually_exclusive_group(required=True)
    source.add_argument("--sql")
    source.add_argument("--sql-file", type=Path)
    for name in ("commit-attempt", "resolve-attempt", "commit-fact", "commit-finding"):
        command = sub.add_parser(name)
        command.add_argument("--db", type=Path, required=True)
        command.add_argument("--scan-id", required=True)
        command.add_argument("--payload", type=Path, required=True)
    task = sub.add_parser("transition-task")
    task.add_argument("--db", type=Path, required=True)
    task.add_argument("--scan-id", required=True)
    task.add_argument("--stage-run-id", required=True)
    task.add_argument("--task-id", required=True)
    task.add_argument("--status", choices=("running", "completed", "skipped", "failed"), required=True)
    task.add_argument("--reason")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "query":
            sql = args.sql if args.sql is not None else args.sql_file.read_text(encoding="utf-8")
            result = query(args.db, sql)
        elif args.command == "commit-attempt":
            result = commit_attempt(args.db, args.scan_id, args.payload)
        elif args.command == "resolve-attempt":
            result = resolve_attempt(args.db, args.scan_id, args.payload)
        elif args.command == "commit-fact":
            result = commit_fact(args.db, args.scan_id, args.payload)
        elif args.command == "commit-finding":
            result = commit_finding(args.db, args.scan_id, args.payload)
        else:
            result = transition_task(
                args.db, args.scan_id, args.stage_run_id, args.task_id,
                args.status, args.reason,
            )
        print(json.dumps(result, ensure_ascii=False, default=str))
        return 0
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError, sqlite3.Error) as exc:
        print(f"aidast-db: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
