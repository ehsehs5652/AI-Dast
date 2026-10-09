.bail on
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;
INSERT OR IGNORE INTO attack_facts (
    fact_id, scan_id, fact_type, fact_key, fact_value, confidence,
    source_endpoint_id, source_finding_id
)
SELECT
    COALESCE(json_extract(payload, '$.fact_id'), 'fact_' || lower(hex(randomblob(12)))),
    @scan_id,
    json_extract(payload, '$.fact_type'),
    json_extract(payload, '$.fact_key'),
    json_extract(payload, '$.fact_value'),
    COALESCE(json_extract(payload, '$.confidence'), 1.0),
    NULLIF(json_extract(payload, '$.source_endpoint_id'), ''),
    NULLIF(json_extract(payload, '$.source_finding_id'), '')
FROM (SELECT CAST(readfile(@payload_path) AS TEXT) AS payload)
WHERE json_valid(payload)
  AND length(trim(json_extract(payload, '$.fact_type'))) > 0
  AND length(trim(json_extract(payload, '$.fact_key'))) > 0;
SELECT changes() AS committed;

