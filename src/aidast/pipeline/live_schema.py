"""Additive schema for the writable post-Recon Pipeline database."""

from __future__ import annotations

import sqlite3


LIVE_PIPELINE_SCHEMA = """
CREATE TABLE IF NOT EXISTS pipeline_sources (
    scan_id TEXT PRIMARY KEY NOT NULL REFERENCES scans(scan_id),
    source_manifest_path TEXT NOT NULL,
    source_manifest_sha256 TEXT NOT NULL CHECK(length(source_manifest_sha256)=64),
    source_database_path TEXT NOT NULL,
    source_database_sha256 TEXT NOT NULL CHECK(length(source_database_sha256)=64),
    materialized_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TRIGGER IF NOT EXISTS pipeline_sources_no_update
BEFORE UPDATE ON pipeline_sources
BEGIN SELECT RAISE(ABORT, 'pipeline source provenance is immutable'); END;
CREATE TRIGGER IF NOT EXISTS pipeline_sources_no_delete
BEFORE DELETE ON pipeline_sources
BEGIN SELECT RAISE(ABORT, 'pipeline source provenance is immutable'); END;

CREATE TABLE IF NOT EXISTS attack_http_requests (
    request_id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    stage_run_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    policy_id TEXT NOT NULL CHECK(length(trim(policy_id)) > 0),
    method TEXT NOT NULL CHECK(length(trim(method)) > 0),
    url TEXT NOT NULL CHECK(length(trim(url)) > 0),
    identity_role TEXT NOT NULL DEFAULT 'unauthenticated'
        CHECK(length(trim(identity_role)) > 0),
    request_fingerprint TEXT NOT NULL CHECK(length(request_fingerprint) = 64),
    status TEXT NOT NULL CHECK(status IN
        ('reserved','running','completed','failed','outcome_unknown')),
    response_status INTEGER CHECK(response_status IS NULL OR response_status BETWEEN 100 AND 599),
    response_bytes INTEGER CHECK(response_bytes IS NULL OR response_bytes >= 0),
    result_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(result_json)),
    policy_sha256 TEXT CHECK(policy_sha256 IS NULL OR length(policy_sha256)=64),
    authorization_source TEXT CHECK(authorization_source IS NULL OR
        authorization_source IN
        ('scope_safe_method','scope_active_mutation','approved_envelope')),
    authorization_reference_id TEXT,
    endpoint_provenance TEXT CHECK(endpoint_provenance IS NULL OR
        endpoint_provenance IN
        ('network_observed','recon_candidate','agent_proposed')),
    endpoint_reference_id TEXT REFERENCES endpoints(endpoint_id),
    risk_class TEXT CHECK(risk_class IS NULL OR risk_class IN
        ('http_probe','application_mutation','test_resource_create',
         'test_resource_delete','external_side_effect','destructive_or_bulk')),
    error_message TEXT,
    scheduled_at REAL NOT NULL,
    dispatched_at REAL,
    finished_at REAL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(stage_run_id, scan_id) REFERENCES stage_runs(stage_run_id, scan_id),
    FOREIGN KEY(task_id, scan_id) REFERENCES attack_tasks(task_id, scan_id)
);
CREATE INDEX IF NOT EXISTS idx_attack_http_budget
    ON attack_http_requests(scan_id, policy_id, scheduled_at);
CREATE INDEX IF NOT EXISTS idx_attack_http_active
    ON attack_http_requests(stage_run_id, status);

CREATE TABLE IF NOT EXISTS attack_authorization_envelopes (
    envelope_id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    stage_run_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    policy_sha256 TEXT NOT NULL CHECK(length(policy_sha256)=64),
    method TEXT NOT NULL CHECK(method IN ('POST','PUT','PATCH','DELETE')),
    origin TEXT NOT NULL,
    normalized_path TEXT NOT NULL,
    provenance_kind TEXT NOT NULL CHECK(provenance_kind IN ('recon_candidate','agent_proposed')),
    evidence_endpoint_id TEXT REFERENCES endpoints(endpoint_id),
    risk_class TEXT NOT NULL CHECK(risk_class IN
        ('application_mutation','test_resource_create','test_resource_delete',
         'external_side_effect')),
    approval_reason TEXT NOT NULL CHECK(approval_reason IN
        ('external_side_effect','high_impact_path','unproven_delete_ownership')),
    max_requests INTEGER NOT NULL CHECK(max_requests BETWEEN 1 AND 10),
    used_requests INTEGER NOT NULL DEFAULT 0 CHECK(used_requests BETWEEN 0 AND max_requests),
    max_body_bytes INTEGER NOT NULL CHECK(max_body_bytes BETWEEN 0 AND 16384),
    status TEXT NOT NULL CHECK(status IN ('pending','approved','denied','expired')),
    requested_at REAL NOT NULL,
    decided_at REAL,
    expires_at REAL,
    FOREIGN KEY(stage_run_id,scan_id) REFERENCES stage_runs(stage_run_id,scan_id),
    FOREIGN KEY(task_id,scan_id) REFERENCES attack_tasks(task_id,scan_id)
);
CREATE INDEX IF NOT EXISTS idx_attack_authorization_pending
    ON attack_authorization_envelopes(stage_run_id,status,requested_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_attack_authorization_active
    ON attack_authorization_envelopes(
        stage_run_id,task_id,policy_id,method,origin,normalized_path
    ) WHERE status IN ('pending','approved');

CREATE TABLE IF NOT EXISTS chain_candidates (
    candidate_id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    stage_run_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    source_finding_id TEXT NOT NULL,
    chain_id TEXT REFERENCES finding_chains(chain_id),
    status TEXT NOT NULL DEFAULT 'proposed'
        CHECK(status IN ('proposed','testing','evidence_collected','rejected','inconclusive')),
    title TEXT NOT NULL CHECK(length(trim(title)) > 0),
    hypothesis TEXT NOT NULL CHECK(length(trim(hypothesis)) > 0),
    terminal_impact TEXT,
    confidence REAL NOT NULL DEFAULT 0 CHECK(confidence BETWEEN 0 AND 1),
    hypothesis_sha256 TEXT NOT NULL CHECK(length(hypothesis_sha256) = 64),
    resolution_reason TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at TEXT,
    FOREIGN KEY(stage_run_id, scan_id) REFERENCES stage_runs(stage_run_id, scan_id),
    FOREIGN KEY(task_id, scan_id) REFERENCES attack_tasks(task_id, scan_id),
    FOREIGN KEY(source_finding_id, scan_id) REFERENCES findings(finding_id, scan_id),
    UNIQUE(stage_run_id, source_finding_id, hypothesis_sha256)
);
CREATE INDEX IF NOT EXISTS idx_chain_candidates_run
    ON chain_candidates(stage_run_id, status);

CREATE TABLE IF NOT EXISTS chain_candidate_nodes (
    candidate_id TEXT NOT NULL REFERENCES chain_candidates(candidate_id),
    position INTEGER NOT NULL CHECK(position >= 0),
    finding_id TEXT REFERENCES findings(finding_id),
    expected_vuln_type TEXT NOT NULL CHECK(length(trim(expected_vuln_type)) > 0),
    node_role TEXT NOT NULL DEFAULT '',
    PRIMARY KEY(candidate_id, position)
);

CREATE TABLE IF NOT EXISTS chain_candidate_edges (
    candidate_id TEXT NOT NULL REFERENCES chain_candidates(candidate_id),
    edge_position INTEGER NOT NULL CHECK(edge_position >= 0),
    from_position INTEGER NOT NULL CHECK(from_position >= 0),
    to_position INTEGER NOT NULL CHECK(to_position > from_position),
    relationship TEXT NOT NULL CHECK(length(trim(relationship)) > 0),
    evidence_summary TEXT,
    PRIMARY KEY(candidate_id, edge_position),
    FOREIGN KEY(candidate_id, from_position)
        REFERENCES chain_candidate_nodes(candidate_id, position),
    FOREIGN KEY(candidate_id, to_position)
        REFERENCES chain_candidate_nodes(candidate_id, position)
);

CREATE TABLE IF NOT EXISTS chain_evidence (
    chain_evidence_id TEXT PRIMARY KEY NOT NULL,
    candidate_id TEXT NOT NULL REFERENCES chain_candidates(candidate_id),
    evidence_kind TEXT NOT NULL CHECK(length(trim(evidence_kind)) > 0),
    details_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(details_json)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_chain_evidence_candidate
    ON chain_evidence(candidate_id);

CREATE TABLE IF NOT EXISTS chain_executions (
    execution_id TEXT PRIMARY KEY NOT NULL,
    candidate_id TEXT NOT NULL UNIQUE REFERENCES chain_candidates(candidate_id),
    chain_id TEXT UNIQUE REFERENCES finding_chains(chain_id),
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    stage_run_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'running'
        CHECK(status IN ('running','succeeded','rejected','inconclusive','outcome_unknown')),
    reason TEXT,
    terminal_impact TEXT,
    terminal_assertion_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(terminal_assertion_json)),
    started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TEXT,
    FOREIGN KEY(stage_run_id, scan_id) REFERENCES stage_runs(stage_run_id, scan_id),
    FOREIGN KEY(task_id, scan_id) REFERENCES attack_tasks(task_id, scan_id),
    CHECK((status='succeeded' AND chain_id IS NOT NULL)
          OR (status!='succeeded' AND chain_id IS NULL))
);
CREATE INDEX IF NOT EXISTS idx_chain_executions_run
    ON chain_executions(stage_run_id, status);

CREATE TABLE IF NOT EXISTS chain_execution_steps (
    execution_id TEXT NOT NULL REFERENCES chain_executions(execution_id),
    position INTEGER NOT NULL CHECK(position >= 0),
    candidate_node_position INTEGER NOT NULL CHECK(candidate_node_position >= 0),
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    request_id TEXT NOT NULL UNIQUE REFERENCES attack_http_requests(request_id),
    attempt_id TEXT NOT NULL UNIQUE REFERENCES attack_attempts(attempt_id),
    input_binding_hashes_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(input_binding_hashes_json)),
    output_capture_hashes_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(output_capture_hashes_json)),
    assertion_results_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(assertion_results_json)),
    evidence_summary TEXT NOT NULL CHECK(length(trim(evidence_summary)) > 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(execution_id, position),
    UNIQUE(execution_id, candidate_node_position)
);

CREATE TABLE IF NOT EXISTS chain_execution_bindings (
    execution_id TEXT NOT NULL,
    edge_position INTEGER NOT NULL CHECK(edge_position >= 0),
    from_step_position INTEGER NOT NULL CHECK(from_step_position >= 0),
    to_step_position INTEGER NOT NULL CHECK(to_step_position > from_step_position),
    binding_name TEXT NOT NULL CHECK(length(trim(binding_name)) > 0),
    value_sha256 TEXT NOT NULL CHECK(length(value_sha256) = 64),
    source_kind TEXT CHECK(source_kind IS NULL OR source_kind IN ('json_path','response_header')),
    source_path_json TEXT CHECK(source_path_json IS NULL OR json_valid(source_path_json)),
    target_kind TEXT CHECK(target_kind IS NULL OR target_kind IN
        ('path_parameter','query_parameter','request_header','json_body')),
    target_path_json TEXT CHECK(target_path_json IS NULL OR json_valid(target_path_json)),
    PRIMARY KEY(execution_id, edge_position, binding_name),
    FOREIGN KEY(execution_id, from_step_position)
        REFERENCES chain_execution_steps(execution_id, position),
    FOREIGN KEY(execution_id, to_step_position)
        REFERENCES chain_execution_steps(execution_id, position)
);

CREATE TABLE IF NOT EXISTS scope_policy_snapshots (
    scope_sha256 TEXT PRIMARY KEY CHECK(length(scope_sha256)=64),
    scope_markdown TEXT NOT NULL CHECK(length(scope_markdown) > 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS validation_scope_bindings (
    scan_id TEXT PRIMARY KEY REFERENCES scans(scan_id),
    scope_sha256 TEXT NOT NULL REFERENCES scope_policy_snapshots(scope_sha256),
    source_path TEXT,
    approval_digest TEXT CHECK(approval_digest IS NULL OR length(approval_digest)=64),
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS validation_cases (
    case_id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    target_kind TEXT NOT NULL CHECK(target_kind IN ('finding','chain')),
    finding_id TEXT REFERENCES findings(finding_id),
    chain_id TEXT REFERENCES finding_chains(chain_id),
    latest_stage_run_id TEXT NOT NULL REFERENCES stage_runs(stage_run_id),
    decision_stage_run_id TEXT REFERENCES stage_runs(stage_run_id),
    processing_phase TEXT NOT NULL CHECK(processing_phase IN
        ('queued','blind_replay','developing','unblinding','completed','interrupted')),
    current_status TEXT CHECK(current_status IN
        ('CONFIRMED','DISPROVEN','OUT_OF_SCOPE','KNOWN','UNDERPOWERED',
         'BLOCKED','INCONCLUSIVE','CONTESTED')),
    state_version INTEGER NOT NULL DEFAULT 0 CHECK(state_version >= 0),
    attack_skill_name TEXT,
    skill_sha256 TEXT CHECK(skill_sha256 IS NULL OR length(skill_sha256)=64),
    validation_profile_sha256 TEXT CHECK(validation_profile_sha256 IS NULL OR length(validation_profile_sha256)=64),
    source_policy_sha256 TEXT CHECK(source_policy_sha256 IS NULL OR length(source_policy_sha256)=64),
    current_policy_sha256 TEXT CHECK(current_policy_sha256 IS NULL OR length(current_policy_sha256)=64),
    blind_case_sha256 TEXT CHECK(blind_case_sha256 IS NULL OR length(blind_case_sha256)=64),
    blind_assessment_sha256 TEXT CHECK(blind_assessment_sha256 IS NULL OR length(blind_assessment_sha256)=64),
    attack_claim_sha256 TEXT CHECK(attack_claim_sha256 IS NULL OR length(attack_claim_sha256)=64),
    known_source_case_id TEXT REFERENCES validation_cases(case_id),
    impact_boundary INTEGER CHECK(impact_boundary IS NULL OR impact_boundary BETWEEN 0 AND 3),
    impact_sensitivity INTEGER CHECK(impact_sensitivity IS NULL OR impact_sensitivity BETWEEN 0 AND 3),
    impact_actor_requirements INTEGER CHECK(impact_actor_requirements IS NULL OR impact_actor_requirements BETWEEN 0 AND 3),
    impact_score INTEGER CHECK(impact_score IS NULL OR impact_score BETWEEN 0 AND 9),
    severity TEXT CHECK(severity IS NULL OR severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    decision_json TEXT CHECK(decision_json IS NULL OR json_valid(decision_json)),
    decision_sha256 TEXT CHECK(decision_sha256 IS NULL OR length(decision_sha256)=64),
    scope_sha256 TEXT REFERENCES scope_policy_snapshots(scope_sha256),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK((target_kind='finding' AND finding_id IS NOT NULL AND chain_id IS NULL)
       OR (target_kind='chain' AND chain_id IS NOT NULL AND finding_id IS NULL)),
    CHECK((current_status IS NULL AND decision_json IS NULL AND decision_sha256 IS NULL)
       OR (current_status IS NOT NULL AND decision_json IS NOT NULL AND decision_sha256 IS NOT NULL)),
    CHECK(current_status!='KNOWN' OR known_source_case_id IS NOT NULL),
    CHECK(impact_score IS NULL OR impact_score =
        impact_boundary + impact_sensitivity + impact_actor_requirements),
    UNIQUE(case_id, scan_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_validation_case_finding
    ON validation_cases(scan_id, finding_id) WHERE finding_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_validation_case_chain
    ON validation_cases(scan_id, chain_id) WHERE chain_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_validation_cases_stage
    ON validation_cases(latest_stage_run_id, processing_phase);

CREATE TABLE IF NOT EXISTS validation_eligibility_assessments (
    assessment_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES validation_cases(case_id),
    stage_run_id TEXT NOT NULL REFERENCES stage_runs(stage_run_id),
    phase TEXT NOT NULL CHECK(phase IN ('preflight','post_replay')),
    scope_sha256 TEXT NOT NULL REFERENCES scope_policy_snapshots(scope_sha256),
    eligibility TEXT NOT NULL CHECK(eligibility IN
        ('ELIGIBLE','INELIGIBLE','CONDITIONAL','UNKNOWN')),
    exclusion_kind TEXT,
    matched_rule TEXT NOT NULL,
    scope_quote TEXT NOT NULL,
    required_impact_json TEXT NOT NULL CHECK(json_valid(required_impact_json)),
    replay_allowed INTEGER NOT NULL CHECK(replay_allowed IN (0,1)),
    reason TEXT NOT NULL,
    evidence_refs_json TEXT NOT NULL CHECK(json_valid(evidence_refs_json)),
    input_sha256 TEXT NOT NULL CHECK(length(input_sha256)=64),
    output_sha256 TEXT NOT NULL CHECK(length(output_sha256)=64),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(case_id,stage_run_id,phase,input_sha256)
);
CREATE INDEX IF NOT EXISTS idx_validation_eligibility_case_stage_phase_created
    ON validation_eligibility_assessments(case_id,stage_run_id,phase,created_at);

CREATE TABLE IF NOT EXISTS validation_attempts (
    attempt_id TEXT PRIMARY KEY NOT NULL,
    case_id TEXT NOT NULL REFERENCES validation_cases(case_id),
    stage_run_id TEXT NOT NULL REFERENCES stage_runs(stage_run_id),
    batch_no INTEGER NOT NULL CHECK(batch_no >= 1),
    attempt_kind TEXT NOT NULL CHECK(attempt_kind IN
        ('target','positive_control','negative_control')),
    ordinal INTEGER NOT NULL CHECK(ordinal >= 1),
    signal_type TEXT NOT NULL CHECK(signal_type IN
        ('oob_callback','response_diff','error_signature','timing','dom_effect',
         'state_change','authorization_boundary')),
    outcome TEXT NOT NULL CHECK(outcome IN
        ('observed','not_observed','blocked','error','outcome_unknown')),
    signal_observed INTEGER CHECK(signal_observed IS NULL OR signal_observed IN (0,1)),
    blocker_axis TEXT CHECK(blocker_axis IS NULL OR blocker_axis IN
        ('identity_auth','state_setup','encoding_transport','timing_concurrency',
         'environment_topology')),
    observation_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(observation_json)),
    started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TEXT,
    impact_hypothesis_id TEXT REFERENCES validation_impact_hypotheses(hypothesis_id),
    UNIQUE(case_id, stage_run_id, batch_no, attempt_kind, ordinal)
);

CREATE TABLE IF NOT EXISTS validation_development_actions (
    action_id TEXT PRIMARY KEY NOT NULL,
    case_id TEXT NOT NULL REFERENCES validation_cases(case_id),
    stage_run_id TEXT NOT NULL REFERENCES stage_runs(stage_run_id),
    ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 1 AND 2),
    blocker_axis TEXT NOT NULL CHECK(blocker_axis IN
        ('identity_auth','state_setup','encoding_transport','timing_concurrency')),
    action_type TEXT NOT NULL CHECK(length(trim(action_type)) > 0),
    status TEXT NOT NULL CHECK(status IN
        ('planned','running','succeeded','failed','outcome_unknown')),
    details_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(details_json)),
    started_at TEXT,
    finished_at TEXT,
    UNIQUE(case_id, stage_run_id, ordinal)
);

CREATE TABLE IF NOT EXISTS validation_evidence (
    evidence_id TEXT PRIMARY KEY NOT NULL,
    case_id TEXT NOT NULL REFERENCES validation_cases(case_id),
    stage_run_id TEXT NOT NULL REFERENCES stage_runs(stage_run_id),
    attempt_id TEXT REFERENCES validation_attempts(attempt_id),
    development_action_id TEXT REFERENCES validation_development_actions(action_id),
    evidence_kind TEXT NOT NULL CHECK(length(trim(evidence_kind)) > 0),
    details_json TEXT NOT NULL CHECK(
        json_valid(details_json) AND length(CAST(details_json AS BLOB)) <= 8192),
    content_sha256 TEXT NOT NULL CHECK(length(content_sha256)=64),
    content_length INTEGER NOT NULL CHECK(content_length >= 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK((attempt_id IS NULL AND development_action_id IS NULL)
       OR (attempt_id IS NOT NULL AND development_action_id IS NULL)
       OR (attempt_id IS NULL AND development_action_id IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS validation_impact_hypotheses (
    hypothesis_id TEXT PRIMARY KEY NOT NULL,
    case_id TEXT NOT NULL REFERENCES validation_cases(case_id),
    stage_run_id TEXT NOT NULL REFERENCES stage_runs(stage_run_id),
    ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 1 AND 3),
    gap_axis TEXT NOT NULL CHECK(gap_axis IN ('boundary','sensitivity','actor_requirements')),
    path_id TEXT NOT NULL CHECK(length(trim(path_id)) > 0),
    hypothesis_kind TEXT NOT NULL CHECK(length(trim(hypothesis_kind)) > 0),
    current_score INTEGER NOT NULL CHECK(current_score BETWEEN 0 AND 3),
    reason_json TEXT NOT NULL CHECK(json_valid(reason_json)),
    required_preconditions_json TEXT NOT NULL CHECK(json_valid(required_preconditions_json)),
    recommended_actions_json TEXT NOT NULL CHECK(json_valid(recommended_actions_json)),
    expected_signal_json TEXT NOT NULL CHECK(json_valid(expected_signal_json)),
    supporting_evidence_ids_json TEXT NOT NULL CHECK(json_valid(supporting_evidence_ids_json)),
    execution_owner TEXT NOT NULL CHECK(execution_owner IN ('validation','chaining','manual')),
    feasibility TEXT NOT NULL CHECK(feasibility IN ('low','medium','high')),
    potential_impact_json TEXT NOT NULL CHECK(json_valid(potential_impact_json)),
    skill_sha256 TEXT NOT NULL CHECK(length(skill_sha256)=64),
    validation_profile_sha256 TEXT NOT NULL CHECK(length(validation_profile_sha256)=64),
    proposal_sha256 TEXT NOT NULL CHECK(length(proposal_sha256)=64),
    status TEXT NOT NULL DEFAULT 'planned' CHECK(status IN
        ('planned','running','succeeded','failed','skipped','outcome_unknown')),
    agent_id TEXT,
    plan_json TEXT CHECK(plan_json IS NULL OR json_valid(plan_json)),
    plan_sha256 TEXT CHECK(plan_sha256 IS NULL OR length(plan_sha256)=64),
    observation_json TEXT CHECK(observation_json IS NULL OR json_valid(observation_json)),
    observation_sha256 TEXT CHECK(
        observation_sha256 IS NULL OR length(observation_sha256)=64),
    started_at TEXT,
    finished_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK((plan_json IS NULL) = (plan_sha256 IS NULL)),
    CHECK((observation_json IS NULL) = (observation_sha256 IS NULL)),
    UNIQUE(case_id, stage_run_id, ordinal),
    UNIQUE(case_id, stage_run_id, path_id)
);

CREATE TABLE IF NOT EXISTS validation_http_requests (
    request_id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    stage_run_id TEXT NOT NULL REFERENCES stage_runs(stage_run_id),
    case_id TEXT NOT NULL REFERENCES validation_cases(case_id),
    attempt_id TEXT REFERENCES validation_attempts(attempt_id),
    development_action_id TEXT REFERENCES validation_development_actions(action_id),
    policy_id TEXT NOT NULL CHECK(length(trim(policy_id)) > 0),
    policy_sha256 TEXT NOT NULL CHECK(length(policy_sha256)=64),
    method TEXT NOT NULL CHECK(length(trim(method)) > 0),
    url TEXT NOT NULL CHECK(length(trim(url)) > 0),
    request_fingerprint TEXT NOT NULL CHECK(length(request_fingerprint)=64),
    status TEXT NOT NULL CHECK(status IN
        ('reserved','running','completed','failed','outcome_unknown')),
    response_status INTEGER CHECK(response_status IS NULL OR response_status BETWEEN 100 AND 599),
    response_bytes INTEGER CHECK(response_bytes IS NULL OR response_bytes >= 0),
    result_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(result_json)),
    error_message TEXT,
    scheduled_at REAL NOT NULL,
    dispatched_at REAL,
    finished_at REAL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK((attempt_id IS NOT NULL AND development_action_id IS NULL)
       OR (attempt_id IS NULL AND development_action_id IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_validation_http_budget
    ON validation_http_requests(scan_id, policy_id, scheduled_at);
CREATE INDEX IF NOT EXISTS idx_validation_http_active
    ON validation_http_requests(stage_run_id, status);

CREATE TABLE IF NOT EXISTS validation_transport_operations (
    operation_id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    stage_run_id TEXT NOT NULL REFERENCES stage_runs(stage_run_id),
    case_id TEXT NOT NULL REFERENCES validation_cases(case_id),
    attempt_id TEXT NOT NULL REFERENCES validation_attempts(attempt_id),
    policy_id TEXT NOT NULL,
    policy_sha256 TEXT NOT NULL CHECK(length(policy_sha256)=64),
    runtime_kind TEXT NOT NULL CHECK(runtime_kind IN ('multipart','websocket','grpc','concurrent')),
    operation_kind TEXT NOT NULL,
    destination TEXT NOT NULL,
    request_fingerprint TEXT NOT NULL CHECK(length(request_fingerprint)=64),
    execution_group_id TEXT,
    member_ordinal INTEGER,
    concurrency_units INTEGER NOT NULL CHECK(concurrency_units IN (0,1)),
    reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes >= 0),
    request_bytes INTEGER,
    response_bytes INTEGER,
    status TEXT NOT NULL CHECK(status IN ('reserved','running','completed','failed','outcome_unknown')),
    result_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(result_json)),
    error_message TEXT,
    scheduled_at REAL NOT NULL,
    dispatched_at REAL,
    finished_at REAL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(execution_group_id, member_ordinal)
);
CREATE INDEX IF NOT EXISTS idx_validation_transport_budget
    ON validation_transport_operations(scan_id, policy_id, scheduled_at);
CREATE INDEX IF NOT EXISTS idx_validation_transport_active
    ON validation_transport_operations(stage_run_id, status);
CREATE INDEX IF NOT EXISTS idx_validation_transport_attempt
    ON validation_transport_operations(attempt_id, runtime_kind);

CREATE TABLE IF NOT EXISTS finding_reproduction_specs (
    finding_id TEXT PRIMARY KEY NOT NULL REFERENCES findings(finding_id),
    attack_skill_name TEXT NOT NULL CHECK(length(trim(attack_skill_name)) > 0),
    endpoint_id TEXT NOT NULL REFERENCES endpoints(endpoint_id),
    method TEXT NOT NULL CHECK(length(trim(method)) > 0),
    endpoint_template TEXT NOT NULL CHECK(length(trim(endpoint_template)) > 0),
    injection_location TEXT NOT NULL CHECK(
        injection_location IN ('path','query','header','cookie','body')),
    parameter_name TEXT NOT NULL CHECK(length(trim(parameter_name)) > 0),
    payload_template_json TEXT NOT NULL CHECK(json_valid(payload_template_json)),
    required_identity_roles_json TEXT NOT NULL CHECK(json_valid(required_identity_roles_json)),
    source_attempt_ids_json TEXT NOT NULL CHECK(json_valid(source_attempt_ids_json)),
    source_request_ids_json TEXT NOT NULL CHECK(json_valid(source_request_ids_json)),
    payload_structure_sha256 TEXT NOT NULL CHECK(length(payload_structure_sha256)=64),
    source_policy_sha256 TEXT NOT NULL CHECK(length(source_policy_sha256)=64),
    runtime_contract_json TEXT CHECK(runtime_contract_json IS NULL OR json_valid(runtime_contract_json)),
    runtime_contract_sha256 TEXT CHECK(
        runtime_contract_sha256 IS NULL OR length(runtime_contract_sha256)=64),
    development_contract_json TEXT CHECK(
        development_contract_json IS NULL OR json_valid(development_contract_json)),
    development_contract_sha256 TEXT CHECK(
        development_contract_sha256 IS NULL OR length(development_contract_sha256)=64),
    impact_development_contract_json TEXT CHECK(
        impact_development_contract_json IS NULL OR json_valid(impact_development_contract_json)),
    impact_development_contract_sha256 TEXT CHECK(
        impact_development_contract_sha256 IS NULL OR length(impact_development_contract_sha256)=64),
    spec_sha256 TEXT NOT NULL CHECK(length(spec_sha256)=64),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK((runtime_contract_json IS NULL) = (runtime_contract_sha256 IS NULL)),
    CHECK((development_contract_json IS NULL) = (development_contract_sha256 IS NULL)),
    CHECK((impact_development_contract_json IS NULL) =
          (impact_development_contract_sha256 IS NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_active_validation_stage
    ON stage_runs(scan_id)
    WHERE stage='validation' AND status IN ('pending','running');

CREATE TRIGGER IF NOT EXISTS validation_evidence_no_update
BEFORE UPDATE ON validation_evidence
BEGIN SELECT RAISE(ABORT, 'validation evidence is append-only'); END;
CREATE TRIGGER IF NOT EXISTS validation_evidence_no_delete
BEFORE DELETE ON validation_evidence
BEGIN SELECT RAISE(ABORT, 'validation evidence is append-only'); END;
CREATE TRIGGER IF NOT EXISTS scope_policy_snapshots_no_update
BEFORE UPDATE ON scope_policy_snapshots
BEGIN SELECT RAISE(ABORT, 'scope snapshots are append-only'); END;
CREATE TRIGGER IF NOT EXISTS scope_policy_snapshots_no_delete
BEFORE DELETE ON scope_policy_snapshots
BEGIN SELECT RAISE(ABORT, 'scope snapshots are append-only'); END;
CREATE TRIGGER IF NOT EXISTS validation_eligibility_assessments_no_update
BEFORE UPDATE ON validation_eligibility_assessments
BEGIN SELECT RAISE(ABORT, 'eligibility assessments are append-only'); END;
CREATE TRIGGER IF NOT EXISTS validation_eligibility_assessments_no_delete
BEFORE DELETE ON validation_eligibility_assessments
BEGIN SELECT RAISE(ABORT, 'eligibility assessments are append-only'); END;
CREATE TRIGGER IF NOT EXISTS validation_attempts_completed_no_update
BEFORE UPDATE ON validation_attempts
WHEN OLD.finished_at IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'completed validation attempts are immutable'); END;
CREATE TRIGGER IF NOT EXISTS validation_attempts_completed_no_delete
BEFORE DELETE ON validation_attempts
WHEN OLD.finished_at IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'completed validation attempts are immutable'); END;
CREATE TRIGGER IF NOT EXISTS finding_reproduction_specs_no_update
BEFORE UPDATE ON finding_reproduction_specs
BEGIN SELECT RAISE(ABORT, 'finding reproduction specs are immutable'); END;
CREATE TRIGGER IF NOT EXISTS finding_reproduction_specs_no_delete
BEFORE DELETE ON finding_reproduction_specs
BEGIN SELECT RAISE(ABORT, 'finding reproduction specs are immutable'); END;
"""


def _add_attack_attempt_columns(conn: sqlite3.Connection) -> None:
    existing = {
        row[1] for row in conn.execute("PRAGMA table_info(attack_attempts)")
    }
    additions = (
        ("finding_id", "TEXT REFERENCES findings(finding_id)"),
        ("resolution_reason", "TEXT"),
        ("resolved_at", "TEXT"),
    )
    for name, declaration in additions:
        if name not in existing:
            conn.execute(
                f"ALTER TABLE attack_attempts ADD COLUMN {name} {declaration}"
            )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_attack_attempts_finding "
        "ON attack_attempts(finding_id)"
    )


def _add_live_columns(conn: sqlite3.Connection) -> None:
    request_columns = {
        row[1] for row in conn.execute("PRAGMA table_info(attack_http_requests)")
    }
    request_additions = (
        ("identity_role", "TEXT NOT NULL DEFAULT 'unauthenticated'"),
        (
            "result_json",
            "TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(result_json))",
        ),
        (
            "policy_sha256",
            "TEXT CHECK(policy_sha256 IS NULL OR length(policy_sha256)=64)",
        ),
        ("authorization_source", "TEXT"),
        ("authorization_reference_id", "TEXT"),
        ("endpoint_provenance", "TEXT"),
        ("endpoint_reference_id", "TEXT REFERENCES endpoints(endpoint_id)"),
        ("risk_class", "TEXT"),
    )
    for name, declaration in request_additions:
        if name not in request_columns:
            conn.execute(
                f"ALTER TABLE attack_http_requests ADD COLUMN {name} {declaration}"
            )

    envelope_columns = {
        row[1]
        for row in conn.execute("PRAGMA table_info(attack_authorization_envelopes)")
    }
    for name, declaration in (
        ("risk_class", "TEXT NOT NULL DEFAULT 'application_mutation'"),
        ("approval_reason", "TEXT NOT NULL DEFAULT 'high_impact_path'"),
    ):
        if name not in envelope_columns:
            conn.execute(
                "ALTER TABLE attack_authorization_envelopes "
                f"ADD COLUMN {name} {declaration}"
            )

    reproduction_columns = {
        row[1]
        for row in conn.execute("PRAGMA table_info(finding_reproduction_specs)")
    }
    for name, declaration in (
        (
            "runtime_contract_json",
            "TEXT CHECK(runtime_contract_json IS NULL OR json_valid(runtime_contract_json))",
        ),
        (
            "runtime_contract_sha256",
            "TEXT CHECK(runtime_contract_sha256 IS NULL OR length(runtime_contract_sha256)=64)",
        ),
        (
            "development_contract_json",
            "TEXT CHECK(development_contract_json IS NULL OR json_valid(development_contract_json))",
        ),
        (
            "development_contract_sha256",
            "TEXT CHECK(development_contract_sha256 IS NULL OR length(development_contract_sha256)=64)",
        ),
        (
            "impact_development_contract_json",
            "TEXT CHECK(impact_development_contract_json IS NULL OR json_valid(impact_development_contract_json))",
        ),
        (
            "impact_development_contract_sha256",
            "TEXT CHECK(impact_development_contract_sha256 IS NULL OR length(impact_development_contract_sha256)=64)",
        ),
    ):
        if name not in reproduction_columns:
            conn.execute(
                f"ALTER TABLE finding_reproduction_specs ADD COLUMN {name} {declaration}"
            )

    attempt_columns = {
        row[1] for row in conn.execute("PRAGMA table_info(validation_attempts)")
    }
    if "impact_hypothesis_id" not in attempt_columns:
        conn.execute(
            "ALTER TABLE validation_attempts ADD COLUMN impact_hypothesis_id TEXT "
            "REFERENCES validation_impact_hypotheses(hypothesis_id)"
        )

    hypothesis_columns = {
        row[1] for row in conn.execute("PRAGMA table_info(validation_impact_hypotheses)")
    }
    for name, declaration in (
        ("status", "TEXT NOT NULL DEFAULT 'planned'"),
        ("agent_id", "TEXT"),
        ("plan_json", "TEXT"),
        ("plan_sha256", "TEXT"),
        ("observation_json", "TEXT"),
        ("observation_sha256", "TEXT"),
        ("started_at", "TEXT"),
        ("finished_at", "TEXT"),
    ):
        if name not in hypothesis_columns:
            conn.execute(
                f"ALTER TABLE validation_impact_hypotheses ADD COLUMN {name} {declaration}"
            )

    case_columns = {
        row[1] for row in conn.execute("PRAGMA table_info(validation_cases)")
    }
    if "scope_sha256" not in case_columns:
        conn.execute(
            "ALTER TABLE validation_cases ADD COLUMN scope_sha256 TEXT "
            "REFERENCES scope_policy_snapshots(scope_sha256)"
        )


def _remove_known_similarity(conn: sqlite3.Connection) -> None:
    columns = {
        row[1] for row in conn.execute("PRAGMA table_info(validation_cases)")
    }
    if "known_similarity" in columns:
        conn.execute("ALTER TABLE validation_cases DROP COLUMN known_similarity")


def migrate_live_pipeline_schema(conn: sqlite3.Connection) -> None:
    """Upgrade only a writable Recon snapshot copy to shared pipeline v11."""
    from aidast.pipeline.schema import migrate_pipeline_schema

    migrate_pipeline_schema(conn)
    conn.executescript(LIVE_PIPELINE_SCHEMA)
    _remove_known_similarity(conn)
    _add_attack_attempt_columns(conn)
    _add_live_columns(conn)
    conn.execute("PRAGMA user_version=11")
