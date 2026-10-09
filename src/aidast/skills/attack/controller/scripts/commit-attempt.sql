.bail on
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;
INSERT OR IGNORE INTO attack_attempts (
    attempt_id, scan_id, task_id, skill_name, endpoint_id,
    request_fingerprint, method, url, identity_role, payload_variant,
    response_status, response_signature, outcome
)
SELECT
    COALESCE(json_extract(payload, '$.attempt_id'), 'attempt_' || lower(hex(randomblob(12)))),
    @scan_id,
    NULLIF(json_extract(payload, '$.task_id'), ''),
    json_extract(payload, '$.skill_name'),
    NULLIF(json_extract(payload, '$.endpoint_id'), ''),
    json_extract(payload, '$.request_fingerprint'),
    json_extract(payload, '$.method'),
    json_extract(payload, '$.url'),
    COALESCE(json_extract(payload, '$.identity_role'), 'unauthenticated'),
    COALESCE(json_extract(payload, '$.payload_variant'), ''),
    json_extract(payload, '$.response_status'),
    json_extract(payload, '$.response_signature'),
    json_extract(payload, '$.outcome')
FROM (SELECT CAST(readfile(@payload_path) AS TEXT) AS payload)
WHERE json_valid(payload)
  AND length(trim(json_extract(payload, '$.skill_name'))) > 0
  AND length(trim(json_extract(payload, '$.request_fingerprint'))) > 0;
SELECT changes() AS committed;

