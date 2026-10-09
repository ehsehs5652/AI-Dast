"""Standalone parameterized writes for the native Chaining Agent."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from contextlib import closing
from pathlib import Path
from uuid import uuid4


def _payload(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("payload must be one JSON object")
    return value


def _text(value: object, *, required: bool = False, maximum: int = 20_000) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str) or len(value) > maximum or (required and not value.strip()):
        raise ValueError("invalid text field")
    return value


def _running_chain_task(
    conn: sqlite3.Connection, *, scan_id: str, stage_run_id: str, task_id: str,
) -> None:
    row = conn.execute(
        """SELECT s.stage,s.status,t.status,t.skill_name
           FROM attack_tasks t JOIN stage_runs s ON s.stage_run_id=t.stage_run_id
           WHERE t.task_id=? AND t.scan_id=? AND t.stage_run_id=?""",
        (task_id, scan_id, stage_run_id),
    ).fetchone()
    if row != ("chaining", "running", "running", "chain"):
        raise ValueError("chain writes require the configured running chain task")


def _attack_proven_finding(conn: sqlite3.Connection, scan_id: str, finding_id: str) -> None:
    row = conn.execute(
        """SELECT 1 FROM findings f WHERE f.finding_id=? AND f.scan_id=?
             AND f.status IN ('unreviewed','confirmed')
             AND EXISTS (SELECT 1 FROM attack_attempts a
                         WHERE a.finding_id=f.finding_id AND a.outcome='confirmed')""",
        (finding_id, scan_id),
    ).fetchone()
    if row is None:
        raise ValueError("chain references a finding without confirmed Attack evidence")


def commit_candidate(
    db_path: Path, scan_id: str, stage_run_id: str, payload_path: Path,
) -> dict:
    item = _payload(payload_path)
    task_id = _text(item.get("task_id"), required=True, maximum=256)
    source_finding_id = _text(item.get("source_finding_id"), required=True, maximum=256)
    title = _text(item.get("title"), required=True, maximum=200)
    hypothesis = _text(item.get("hypothesis"), required=True)
    confidence = item.get("confidence", 0.0)
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
        raise ValueError("candidate confidence must be between 0 and 1")
    nodes = item.get("nodes")
    edges = item.get("edges")
    if not isinstance(nodes, list) or not 2 <= len(nodes) <= 4:
        raise ValueError("a chain candidate requires two to four nodes")
    if not isinstance(edges, list) or not 1 <= len(edges) <= 3:
        raise ValueError("a chain candidate requires one to three edges")
    if len(edges) != len(nodes) - 1:
        raise ValueError("a complete chain candidate requires one edge between each node")
    digest = hashlib.sha256(" ".join(hypothesis.split()).casefold().encode("utf-8")).hexdigest()
    candidate_id = _text(item.get("candidate_id"), maximum=256) or "candidate_" + uuid4().hex
    with closing(sqlite3.connect(db_path)) as conn, conn:
        conn.execute("PRAGMA foreign_keys=ON")
        _running_chain_task(
            conn, scan_id=scan_id, stage_run_id=stage_run_id, task_id=task_id,
        )
        _attack_proven_finding(conn, scan_id, source_finding_id)
        cursor = conn.execute(
            """INSERT OR IGNORE INTO chain_candidates
               (candidate_id,scan_id,stage_run_id,task_id,source_finding_id,status,
                title,hypothesis,terminal_impact,confidence,hypothesis_sha256)
               VALUES (?,?,?,?,?,'proposed',?,?,?,?,?)""",
            (
                candidate_id, scan_id, stage_run_id, task_id, source_finding_id,
                title, hypothesis, _text(item.get("terminal_impact"), maximum=2000) or None,
                float(confidence), digest,
            ),
        )
        if cursor.rowcount != 1:
            row = conn.execute(
                """SELECT candidate_id FROM chain_candidates
                   WHERE stage_run_id=? AND source_finding_id=? AND hypothesis_sha256=?""",
                (stage_run_id, source_finding_id, digest),
            ).fetchone()
            if row is None:
                raise ValueError("duplicate chain candidate could not be reconciled")
            return {"candidate_id": row[0], "committed": False}
        for position, raw in enumerate(nodes):
            if not isinstance(raw, dict):
                raise ValueError("candidate nodes must be objects")
            finding_id = _text(raw.get("finding_id"), maximum=256) or None
            if finding_id is not None:
                _attack_proven_finding(conn, scan_id, finding_id)
            conn.execute(
                """INSERT INTO chain_candidate_nodes
                   (candidate_id,position,finding_id,expected_vuln_type,node_role)
                   VALUES (?,?,?,?,?)""",
                (
                    candidate_id, position, finding_id,
                    _text(raw.get("expected_vuln_type"), required=True, maximum=128),
                    _text(raw.get("role"), maximum=128),
                ),
            )
        if nodes[0].get("finding_id") != source_finding_id:
            raise ValueError("candidate node zero must be the source finding")
        for edge_position, raw in enumerate(edges):
            if not isinstance(raw, dict):
                raise ValueError("candidate edges must be objects")
            source = raw.get("from_position")
            target = raw.get("to_position")
            if type(source) is not int or type(target) is not int:
                raise ValueError("candidate edge positions must be integers")
            if (source, target) != (edge_position, edge_position + 1):
                raise ValueError("candidate edges must form one ordered linear flow")
            conn.execute(
                """INSERT INTO chain_candidate_edges
                   (candidate_id,edge_position,from_position,to_position,relationship,evidence_summary)
                   VALUES (?,?,?,?,?,?)""",
                (
                    candidate_id, edge_position, source, target,
                    _text(raw.get("relationship"), required=True, maximum=2000),
                    _text(raw.get("evidence_summary"), maximum=2000) or None,
                ),
            )
        return {"candidate_id": candidate_id, "committed": True}


def begin_execution(
    db_path: Path, scan_id: str, stage_run_id: str, payload_path: Path,
) -> dict:
    item = _payload(payload_path)
    task_id = _text(item.get("task_id"), required=True, maximum=256)
    candidate_id = _text(item.get("candidate_id"), required=True, maximum=256)
    execution_id = (
        _text(item.get("execution_id"), maximum=256) or "chainexec_" + uuid4().hex
    )
    with closing(sqlite3.connect(db_path)) as conn, conn:
        conn.execute("PRAGMA foreign_keys=ON")
        _running_chain_task(
            conn, scan_id=scan_id, stage_run_id=stage_run_id, task_id=task_id,
        )
        candidate = conn.execute(
            """SELECT status,terminal_impact FROM chain_candidates
               WHERE candidate_id=? AND scan_id=? AND stage_run_id=? AND task_id=?""",
            (candidate_id, scan_id, stage_run_id, task_id),
        ).fetchone()
        if candidate is None or candidate[0] != "proposed":
            raise ValueError("chain execution requires a proposed candidate")
        nodes = conn.execute(
            """SELECT position,finding_id FROM chain_candidate_nodes
               WHERE candidate_id=? ORDER BY position""",
            (candidate_id,),
        ).fetchall()
        if not 2 <= len(nodes) <= 4 or [row[0] for row in nodes] != list(range(len(nodes))):
            raise ValueError("chain execution requires two to four ordered nodes")
        if any(row[1] is None for row in nodes):
            raise ValueError("unproven expected nodes cannot be executed as a complete chain")
        if len({row[1] for row in nodes}) < 2:
            raise ValueError("a complete chain requires at least two proven findings")
        for _, finding_id in nodes:
            _attack_proven_finding(conn, scan_id, finding_id)
        cursor = conn.execute(
            """INSERT INTO chain_executions
               (execution_id,candidate_id,scan_id,stage_run_id,task_id,status,terminal_impact)
               VALUES (?,?,?,?,?,'running',?)""",
            (
                execution_id, candidate_id, scan_id, stage_run_id, task_id,
                candidate[1],
            ),
        )
        if cursor.rowcount != 1:
            raise ValueError("chain execution could not be started")
        conn.execute(
            "UPDATE chain_candidates SET status='testing' WHERE candidate_id=?",
            (candidate_id,),
        )
        return {
            "execution_id": execution_id, "candidate_id": candidate_id,
            "status": "running", "step_count": len(nodes),
        }


def _hash_object(value: object, *, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or len(value) > 16:
        raise ValueError(f"{label} must be a bounded object")
    result: dict[str, str] = {}
    for name, digest in value.items():
        if (
            not isinstance(name, str) or not name.strip() or len(name) > 128
            or not isinstance(digest, str) or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ValueError(f"{label} contains an invalid hash")
        result[name] = digest
    return result


def _binding_contracts(value: object, *, source: bool) -> dict[str, dict]:
    if value is None:
        return {}
    if not isinstance(value, dict) or len(value) > 16:
        raise ValueError("binding contracts must be a bounded object")
    allowed = {"json_path", "response_header"} if source else {
        "path_parameter", "query_parameter", "request_header", "json_body",
    }
    result = {}
    for name, raw in value.items():
        if not isinstance(name, str) or not name.strip() or len(name) > 128 or not isinstance(raw, dict):
            raise ValueError("binding contract contains an invalid entry")
        kind_key = "source_kind" if source else "target_kind"
        path_key = "source_path" if source else "target_path"
        kind, path = raw.get(kind_key), raw.get(path_key)
        if kind not in allowed or not isinstance(path, list) or not 1 <= len(path) <= 16:
            raise ValueError("binding contract contains an invalid kind or path")
        if any(
            (isinstance(part, str) and (not part or len(part) > 256))
            or (type(part) is int and part < 0)
            or type(part) not in {str, int}
            for part in path
        ):
            raise ValueError("binding contract path is invalid")
        if kind in {"response_header", "path_parameter", "query_parameter", "request_header"} \
                and (len(path) != 1 or not isinstance(path[0], str)):
            raise ValueError("non-JSON binding paths require one name")
        result[name] = {kind_key: kind, path_key: path}
    return result


def record_execution_step(
    db_path: Path, scan_id: str, stage_run_id: str, payload_path: Path,
) -> dict:
    item = _payload(payload_path)
    task_id = _text(item.get("task_id"), required=True, maximum=256)
    execution_id = _text(item.get("execution_id"), required=True, maximum=256)
    request_id = _text(item.get("request_id"), required=True, maximum=256)
    attempt_id = _text(item.get("attempt_id"), required=True, maximum=256)
    finding_id = _text(item.get("finding_id"), required=True, maximum=256)
    position = item.get("position")
    if type(position) is not int or not 0 <= position <= 3:
        raise ValueError("execution step position must be between zero and three")
    evidence_summary = _text(
        item.get("evidence_summary"), required=True, maximum=2000
    )
    with closing(sqlite3.connect(db_path)) as conn, conn:
        conn.execute("PRAGMA foreign_keys=ON")
        _running_chain_task(
            conn, scan_id=scan_id, stage_run_id=stage_run_id, task_id=task_id,
        )
        execution = conn.execute(
            """SELECT candidate_id,status FROM chain_executions
               WHERE execution_id=? AND scan_id=? AND stage_run_id=? AND task_id=?""",
            (execution_id, scan_id, stage_run_id, task_id),
        ).fetchone()
        if execution is None or execution[1] != "running":
            raise ValueError("execution step requires the configured running execution")
        node = conn.execute(
            """SELECT finding_id FROM chain_candidate_nodes
               WHERE candidate_id=? AND position=?""",
            (execution[0], position),
        ).fetchone()
        if node is None or node[0] != finding_id:
            raise ValueError("execution step does not match its candidate node")
        request = conn.execute(
            """SELECT request_fingerprint,result_json FROM attack_http_requests
               WHERE request_id=? AND scan_id=? AND stage_run_id=? AND task_id=?
                 AND status='completed'""",
            (request_id, scan_id, stage_run_id, task_id),
        ).fetchone()
        attempt = conn.execute(
            """SELECT request_fingerprint,outcome,finding_id FROM attack_attempts
               WHERE attempt_id=? AND scan_id=? AND task_id=? AND skill_name='chain'""",
            (attempt_id, scan_id, task_id),
        ).fetchone()
        if request is None or attempt is None or request[0] != attempt[0]:
            raise ValueError("execution request and attempt evidence do not correspond")
        if attempt[1] != "lead" or attempt[2] is not None:
            raise ValueError("execution step requires an unresolved chain lead")
        try:
            request_result = json.loads(request[1])
            inputs = _hash_object(
                request_result.get("consumed_binding_hashes", {}),
                label="input binding hashes",
            )
            outputs = _hash_object(
                request_result.get("capture_hashes", {}),
                label="output capture hashes",
            )
            assertions = request_result.get("assertions", [])
            _binding_contracts(
                request_result.get("capture_contracts"), source=True,
            )
            _binding_contracts(
                request_result.get("consumed_binding_contracts"), source=False,
            )
        except (AttributeError, TypeError, json.JSONDecodeError) as exc:
            raise ValueError("execution request metadata is invalid") from exc
        if not isinstance(assertions, list) or len(assertions) > 16:
            raise ValueError("execution assertion metadata is invalid")
        conn.execute(
            """INSERT INTO chain_execution_steps
               (execution_id,position,candidate_node_position,finding_id,request_id,
                attempt_id,input_binding_hashes_json,output_capture_hashes_json,
                assertion_results_json,evidence_summary)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                execution_id, position, position, finding_id, request_id, attempt_id,
                json.dumps(inputs, sort_keys=True), json.dumps(outputs, sort_keys=True),
                json.dumps(assertions, sort_keys=True), evidence_summary,
            ),
        )
        # Contracts stay with the immutable request result until finish_execution
        # proves that the captured and consumed value hashes are identical.
        return {
            "execution_id": execution_id, "position": position,
            "request_id": request_id, "attempt_id": attempt_id,
        }


def finish_execution(
    db_path: Path, scan_id: str, stage_run_id: str, payload_path: Path,
) -> dict:
    item = _payload(payload_path)
    task_id = _text(item.get("task_id"), required=True, maximum=256)
    execution_id = _text(item.get("execution_id"), required=True, maximum=256)
    outcome = _text(item.get("outcome"), required=True, maximum=32).casefold()
    if outcome not in {"succeeded", "rejected", "inconclusive"}:
        raise ValueError("execution outcome must be succeeded, rejected or inconclusive")
    reason = _text(item.get("reason"), required=True, maximum=2000)
    with closing(sqlite3.connect(db_path)) as conn, conn:
        conn.execute("PRAGMA foreign_keys=ON")
        _running_chain_task(
            conn, scan_id=scan_id, stage_run_id=stage_run_id, task_id=task_id,
        )
        execution = conn.execute(
            """SELECT candidate_id,status,terminal_impact FROM chain_executions
               WHERE execution_id=? AND scan_id=? AND stage_run_id=? AND task_id=?""",
            (execution_id, scan_id, stage_run_id, task_id),
        ).fetchone()
        if execution is None or execution[1] != "running":
            raise ValueError("chain execution is not running")
        candidate_id, _, terminal_impact = execution
        steps = conn.execute(
            """SELECT position,finding_id,request_id,attempt_id,
                      input_binding_hashes_json,output_capture_hashes_json,
                      assertion_results_json,evidence_summary
               FROM chain_execution_steps WHERE execution_id=? ORDER BY position""",
            (execution_id,),
        ).fetchall()
        if outcome != "succeeded":
            for step in steps:
                conn.execute(
                    """UPDATE attack_attempts SET outcome=?,resolution_reason=?,
                       resolved_at=CURRENT_TIMESTAMP WHERE attempt_id=? AND outcome='lead'
                       AND finding_id IS NULL""",
                    (outcome, reason, step[3]),
                )
            conn.execute(
                """UPDATE chain_executions SET status=?,reason=?,finished_at=CURRENT_TIMESTAMP
                   WHERE execution_id=?""",
                (outcome, reason, execution_id),
            )
            conn.execute(
                """UPDATE chain_candidates SET status=?,resolution_reason=?,
                   resolved_at=CURRENT_TIMESTAMP WHERE candidate_id=?""",
                (outcome, reason, candidate_id),
            )
            return {"execution_id": execution_id, "status": outcome, "chain_id": None}

        nodes = conn.execute(
            """SELECT position,finding_id FROM chain_candidate_nodes
               WHERE candidate_id=? ORDER BY position""",
            (candidate_id,),
        ).fetchall()
        if len(steps) != len(nodes) or [step[0] for step in steps] != list(range(len(nodes))):
            raise ValueError("successful execution requires one current request per chain node")
        if any(step[1] != nodes[position][1] for position, step in enumerate(steps)):
            raise ValueError("execution steps do not exactly match candidate findings")
        edges = conn.execute(
            """SELECT edge_position,from_position,to_position FROM chain_candidate_edges
               WHERE candidate_id=? ORDER BY edge_position""",
            (candidate_id,),
        ).fetchall()
        for edge_position, source_position, target_position in edges:
            outputs = _hash_object(
                json.loads(steps[source_position][5]), label="stored output captures"
            )
            inputs = _hash_object(
                json.loads(steps[target_position][4]), label="stored input bindings"
            )
            matches = sorted(
                (output_name, input_name, digest)
                for output_name, digest in outputs.items()
                for input_name, input_digest in inputs.items()
                if digest == input_digest
            )
            if not matches:
                raise ValueError("every chain edge requires a captured value used by its next request")
            output_name, input_name, digest = matches[0]
            source_kind = source_path = target_kind = target_path = None
            source_result = json.loads(conn.execute(
                "SELECT result_json FROM attack_http_requests WHERE request_id=?",
                (steps[source_position][2],),
            ).fetchone()[0])
            target_result = json.loads(conn.execute(
                "SELECT result_json FROM attack_http_requests WHERE request_id=?",
                (steps[target_position][2],),
            ).fetchone()[0])
            source_contract = _binding_contracts(
                source_result.get("capture_contracts"), source=True,
            ).get(output_name)
            target_contract = _binding_contracts(
                target_result.get("consumed_binding_contracts"), source=False,
            ).get(input_name)
            if source_contract is not None and target_contract is not None:
                source_kind = source_contract["source_kind"]
                source_path = json.dumps(source_contract["source_path"], separators=(",", ":"))
                target_kind = target_contract["target_kind"]
                target_path = json.dumps(target_contract["target_path"], separators=(",", ":"))
            conn.execute(
                """INSERT INTO chain_execution_bindings
                   (execution_id,edge_position,from_step_position,to_step_position,
                    binding_name,value_sha256,source_kind,source_path_json,
                    target_kind,target_path_json) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    execution_id, edge_position, source_position, target_position,
                    output_name, digest, source_kind, source_path, target_kind, target_path,
                ),
            )
        try:
            final_assertions = json.loads(steps[-1][6])
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("final assertion evidence is invalid") from exc
        terminal_assertions = [
            assertion for assertion in final_assertions
            if isinstance(assertion, dict) and assertion.get("terminal") is True
            and assertion.get("kind") != "status_equals"
        ]
        if not terminal_assertions or not all(
            assertion.get("passed") is True for assertion in terminal_assertions
        ):
            raise ValueError("successful execution requires a passed terminal impact assertion")
        if not isinstance(terminal_impact, str) or not terminal_impact.strip():
            raise ValueError("successful execution requires a declared terminal impact")
        finding_ids = [row[1] for row in nodes]
        for finding_id in finding_ids:
            _attack_proven_finding(conn, scan_id, finding_id)
        severity = _text(item.get("combined_severity"), required=True).upper()
        if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            raise ValueError("invalid combined severity")
        chain_id = _text(item.get("chain_id"), maximum=256) or "chain_" + uuid4().hex
        conn.execute(
            """INSERT INTO finding_chains
               (chain_id,scan_id,title,combined_severity,description,status)
               VALUES (?,?,?,?,?,'proposed')""",
            (
                chain_id, scan_id,
                _text(item.get("title"), required=True, maximum=200), severity,
                _text(item.get("description"), required=True),
            ),
        )
        roles = item.get("roles", [])
        if roles and (not isinstance(roles, list) or len(roles) != len(finding_ids)):
            raise ValueError("chain roles must align with finding IDs")
        for position, finding_id in enumerate(finding_ids):
            role = _text(roles[position], maximum=256) if roles else ""
            conn.execute(
                "INSERT INTO finding_chain_nodes(chain_id,finding_id,position,role) VALUES (?,?,?,?)",
                (chain_id, finding_id, position, role),
            )
            cursor = conn.execute(
                """UPDATE attack_attempts SET outcome='confirmed',finding_id=?,
                   resolution_reason='confirmed by complete chain replay',
                   resolved_at=CURRENT_TIMESTAMP WHERE attempt_id=? AND outcome='lead'
                   AND finding_id IS NULL""",
                (finding_id, steps[position][3]),
            )
            if cursor.rowcount != 1:
                raise ValueError("chain replay attempt could not be confirmed")
            conn.execute(
                """INSERT INTO chain_evidence
                   (chain_evidence_id,candidate_id,evidence_kind,details_json)
                   VALUES (?,?,'executed_step',?)""",
                (
                    "chainev_" + uuid4().hex, candidate_id,
                    json.dumps({
                        "position": position, "request_id": steps[position][2],
                        "attempt_id": steps[position][3],
                        "assertions": json.loads(steps[position][6]),
                        "summary": steps[position][7],
                    }, ensure_ascii=False, allow_nan=False),
                ),
            )
        terminal_json = json.dumps(
            terminal_assertions, ensure_ascii=False, sort_keys=True, allow_nan=False
        )
        conn.execute(
            """UPDATE chain_executions SET status='succeeded',chain_id=?,reason=?,
               terminal_assertion_json=?,finished_at=CURRENT_TIMESTAMP
               WHERE execution_id=?""",
            (chain_id, reason, terminal_json, execution_id),
        )
        conn.execute(
            """UPDATE chain_candidates SET status='evidence_collected',chain_id=?,
               confidence=1.0,resolution_reason=?,resolved_at=CURRENT_TIMESTAMP
               WHERE candidate_id=?""",
            (chain_id, reason, candidate_id),
        )
        return {"execution_id": execution_id, "status": "succeeded", "chain_id": chain_id}


def resolve_candidate(
    db_path: Path, scan_id: str, stage_run_id: str, payload_path: Path,
) -> dict:
    item = _payload(payload_path)
    task_id = _text(item.get("task_id"), required=True, maximum=256)
    candidate_id = _text(item.get("candidate_id"), required=True, maximum=256)
    resolution = _text(item.get("resolution"), required=True, maximum=32).casefold()
    if resolution not in {"rejected", "inconclusive"}:
        raise ValueError("candidate resolution must be rejected or inconclusive")
    reason = _text(item.get("reason"), required=True, maximum=2000)
    with closing(sqlite3.connect(db_path)) as conn, conn:
        conn.execute("PRAGMA foreign_keys=ON")
        _running_chain_task(
            conn, scan_id=scan_id, stage_run_id=stage_run_id, task_id=task_id,
        )
        cursor = conn.execute(
            """UPDATE chain_candidates SET status=?,resolution_reason=?,resolved_at=CURRENT_TIMESTAMP
               WHERE candidate_id=? AND scan_id=? AND stage_run_id=? AND task_id=?
                 AND status IN ('proposed','testing')""",
            (resolution, reason, candidate_id, scan_id, stage_run_id, task_id),
        )
        if cursor.rowcount != 1:
            raise ValueError("candidate is not open for this chain task")
        return {"candidate_id": candidate_id, "status": resolution}


def commit_chain(
    db_path: Path, scan_id: str, stage_run_id: str, payload_path: Path,
) -> dict:
    item = _payload(payload_path)
    task_id = _text(item.get("task_id"), required=True, maximum=256)
    candidate_id = _text(item.get("candidate_id"), required=True, maximum=256)
    finding_ids = item.get("finding_ids")
    if not isinstance(finding_ids, list) or not 2 <= len(finding_ids) <= 4:
        raise ValueError("a proposed chain requires two to four finding IDs")
    if any(not isinstance(value, str) or not value.strip() for value in finding_ids):
        raise ValueError("invalid chain finding ID")
    if len(finding_ids) != len(set(finding_ids)):
        raise ValueError("chain finding IDs must be unique")
    severity = _text(item.get("combined_severity"), required=True).upper()
    if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
        raise ValueError("invalid combined severity")
    evidence = item.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise ValueError("a chain requires evidence for its connecting edge")
    chain_id = _text(item.get("chain_id"), maximum=256) or "chain_" + uuid4().hex
    with closing(sqlite3.connect(db_path)) as conn, conn:
        conn.execute("PRAGMA foreign_keys=ON")
        _running_chain_task(
            conn, scan_id=scan_id, stage_run_id=stage_run_id, task_id=task_id,
        )
        candidate = conn.execute(
            """SELECT source_finding_id,status FROM chain_candidates
               WHERE candidate_id=? AND scan_id=? AND stage_run_id=? AND task_id=?""",
            (candidate_id, scan_id, stage_run_id, task_id),
        ).fetchone()
        if candidate is None or candidate[1] not in {"proposed", "testing"}:
            raise ValueError("chain candidate is not open")
        if candidate[0] not in finding_ids:
            raise ValueError("chain omits its source finding")
        for finding_id in finding_ids:
            _attack_proven_finding(conn, scan_id, finding_id)
        conn.execute(
            """INSERT INTO finding_chains
               (chain_id,scan_id,title,combined_severity,description,status)
               VALUES (?,?,?,?,?,'proposed')""",
            (
                chain_id, scan_id,
                _text(item.get("title"), required=True, maximum=200), severity,
                _text(item.get("description"), required=True),
            ),
        )
        roles = item.get("roles", [])
        if roles and (not isinstance(roles, list) or len(roles) != len(finding_ids)):
            raise ValueError("chain roles must align with finding IDs")
        for position, finding_id in enumerate(finding_ids):
            conn.execute(
                "INSERT INTO finding_chain_nodes(chain_id,finding_id,position,role) VALUES (?,?,?,?)",
                (chain_id, finding_id, position, roles[position] if roles else ""),
            )
        for raw in evidence:
            if not isinstance(raw, dict):
                raise ValueError("chain evidence must contain objects")
            conn.execute(
                """INSERT INTO chain_evidence
                   (chain_evidence_id,candidate_id,evidence_kind,details_json)
                   VALUES (?,?,?,?)""",
                (
                    "chainev_" + uuid4().hex, candidate_id,
                    _text(raw.get("kind"), required=True, maximum=128),
                    json.dumps(raw.get("details", {}), ensure_ascii=False, allow_nan=False),
                ),
            )
        conn.execute(
            """UPDATE chain_candidates SET status='evidence_collected',chain_id=?,
               confidence=1.0,resolved_at=CURRENT_TIMESTAMP WHERE candidate_id=?""",
            (chain_id, candidate_id),
        )
        return {"candidate_id": candidate_id, "chain_id": chain_id, "status": "proposed"}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    for name in (
        "commit-candidate", "resolve-candidate", "commit-chain",
        "begin-execution", "record-execution-step", "finish-execution",
    ):
        command = sub.add_parser(name)
        command.add_argument("--db", type=Path, required=True)
        command.add_argument("--scan-id", required=True)
        command.add_argument("--stage-run-id", required=True)
        command.add_argument("--payload", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        function = {
            "commit-candidate": commit_candidate,
            "resolve-candidate": resolve_candidate,
            "commit-chain": commit_chain,
            "begin-execution": begin_execution,
            "record-execution-step": record_execution_step,
            "finish-execution": finish_execution,
        }[args.command]
        result = function(args.db, args.scan_id, args.stage_run_id, args.payload)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError, sqlite3.Error) as exc:
        print(f"aidast-chain: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
