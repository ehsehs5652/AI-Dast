.bail on
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;
BEGIN IMMEDIATE;

CREATE TEMP TABLE _chain_input(payload TEXT NOT NULL CHECK (json_valid(payload)));
INSERT INTO _chain_input VALUES (CAST(readfile(@payload_path) AS TEXT));
CREATE TEMP TABLE _chain_guard(ok INTEGER NOT NULL CHECK (ok = 1));

INSERT INTO _chain_guard
SELECT json_extract(payload, '$.scan_id') = @scan_id FROM _chain_input;
INSERT INTO _chain_guard
SELECT json_extract(payload, '$.combined_severity') IN ('CRITICAL','HIGH','MEDIUM','LOW')
FROM _chain_input;
INSERT INTO _chain_guard
SELECT json_array_length(payload, '$.nodes') >= 2 FROM _chain_input;
INSERT INTO _chain_guard
SELECT NOT EXISTS (
    SELECT 1 FROM finding_chains
    WHERE chain_id = json_extract(payload, '$.chain_id')
) FROM _chain_input;
INSERT INTO _chain_guard
SELECT NOT EXISTS (
    SELECT 1
    FROM _chain_input i, json_each(i.payload, '$.nodes') n
    LEFT JOIN findings f
      ON f.finding_id = json_extract(n.value, '$.finding_id')
     AND f.scan_id = @scan_id
    WHERE f.finding_id IS NULL
) FROM _chain_input;

INSERT INTO finding_chains (
    chain_id, scan_id, title, combined_severity, description, status
)
SELECT
    json_extract(payload, '$.chain_id'), @scan_id,
    json_extract(payload, '$.title'),
    json_extract(payload, '$.combined_severity'),
    json_extract(payload, '$.description'), 'demonstrated'
FROM _chain_input;

INSERT INTO finding_chain_nodes (chain_id, finding_id, position, role)
SELECT
    json_extract(i.payload, '$.chain_id'),
    json_extract(n.value, '$.finding_id'),
    CAST(json_extract(n.value, '$.position') AS INTEGER),
    COALESCE(json_extract(n.value, '$.role'), '')
FROM _chain_input i, json_each(i.payload, '$.nodes') n;

COMMIT;
SELECT json_extract(payload, '$.chain_id') AS chain_id FROM _chain_input;

