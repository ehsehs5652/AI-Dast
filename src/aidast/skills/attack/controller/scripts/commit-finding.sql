.bail on
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;
BEGIN IMMEDIATE;

CREATE TEMP TABLE _finding_input(payload TEXT NOT NULL CHECK (json_valid(payload)));
INSERT INTO _finding_input VALUES (CAST(readfile(@payload_path) AS TEXT));
CREATE TEMP TABLE _finding_guard(ok INTEGER NOT NULL CHECK (ok = 1));

INSERT INTO _finding_guard VALUES (
    COALESCE((SELECT status = 'completed' FROM scans WHERE scan_id = @scan_id), 0)
);
INSERT INTO _finding_guard
SELECT json_extract(payload, '$.scan_id') = @scan_id FROM _finding_input;
INSERT INTO _finding_guard
SELECT json_type(payload, '$.evidence') = 'array' FROM _finding_input;
INSERT INTO _finding_guard
SELECT json_extract(payload, '$.severity') IN ('CRITICAL','HIGH','MEDIUM','LOW')
FROM _finding_input;
INSERT INTO _finding_guard
SELECT length(trim(json_extract(payload, '$.vuln_type'))) > 0 FROM _finding_input;
INSERT INTO _finding_guard
SELECT length(trim(json_extract(payload, '$.title'))) > 0 FROM _finding_input;
INSERT INTO _finding_guard
SELECT NOT EXISTS (
    SELECT 1 FROM findings f
    WHERE f.finding_id = json_extract(payload, '$.finding_id')
) FROM _finding_input;
INSERT INTO _finding_guard
SELECT CASE
    WHEN NULLIF(json_extract(payload, '$.endpoint_id'), '') IS NULL THEN 1
    ELSE EXISTS (
        SELECT 1 FROM endpoints e
        JOIN origins o ON o.origin_id = e.origin_id
        JOIN assets a ON a.asset_id = o.asset_id
        WHERE e.endpoint_id = json_extract(payload, '$.endpoint_id')
          AND a.scan_id = @scan_id
    )
END FROM _finding_input;

INSERT INTO findings (
    finding_id, scan_id, endpoint_id, vuln_type, severity, title, description,
    cvss_score, cvss_vector, cwe_id
)
SELECT
    json_extract(payload, '$.finding_id'),
    @scan_id,
    NULLIF(json_extract(payload, '$.endpoint_id'), ''),
    json_extract(payload, '$.vuln_type'),
    json_extract(payload, '$.severity'),
    json_extract(payload, '$.title'),
    json_extract(payload, '$.description'),
    json_extract(payload, '$.cvss_score'),
    json_extract(payload, '$.cvss_vector'),
    NULLIF(json_extract(payload, '$.cwe_id'), '')
FROM _finding_input;

INSERT INTO attack_requests (
    request_id, finding_id, role, method, url, request_headers, request_body,
    response_status, response_headers, response_body, response_time_ms
)
SELECT
    'areq_' || lower(hex(randomblob(12))),
    json_extract(i.payload, '$.finding_id'),
    COALESCE(json_extract(e.value, '$.role'), 'unknown'),
    COALESCE(json_extract(e.value, '$.method'), 'GET'),
    COALESCE(json_extract(e.value, '$.url'), ''),
    json_extract(e.value, '$.request_headers'),
    CASE WHEN length(json_extract(e.value, '$.request_body')) > 10000
         THEN substr(json_extract(e.value, '$.request_body'), 1, 10000)
              || char(10) || '... (truncated)'
         ELSE json_extract(e.value, '$.request_body') END,
    json_extract(e.value, '$.response_status'),
    json_extract(e.value, '$.response_headers'),
    CASE WHEN length(json_extract(e.value, '$.response_body')) > 10000
         THEN substr(json_extract(e.value, '$.response_body'), 1, 10000)
              || char(10) || '... (truncated)'
         ELSE json_extract(e.value, '$.response_body') END,
    json_extract(e.value, '$.response_time_ms')
FROM _finding_input i, json_each(i.payload, '$.evidence') e;

COMMIT;
SELECT json_extract(payload, '$.finding_id') AS finding_id FROM _finding_input;

