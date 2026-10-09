# Shared pipeline database contract

Use only `pipeline_db_path` and `db_helper_path` from `config.json`. Invoke the
helper with the configured `python_executable`. Never search for another DB.

Read rows with:

```text
PYTHON DB_HELPER query --db PIPELINE_DB --sql-file QUERY.sql
```

The query command opens SQLite read-only. Build endpoint URLs from
`origins.base_url` plus `endpoints.path`. Select rows for one scan through:

```sql
SELECT e.endpoint_id,e.method,e.path,e.normalized_path,e.auth_required,
       o.base_url,p.name,p.location,p.example_value,p.is_identifier
FROM endpoints e
JOIN origins o ON o.origin_id=e.origin_id
JOIN assets a ON a.asset_id=o.asset_id
LEFT JOIN parameters p ON p.endpoint_id=e.endpoint_id
WHERE a.scan_id='SCAN_ID' AND e.is_excluded=0;
```

Write one JSON object at a time with:

```text
PYTHON DB_HELPER commit-attempt --db PIPELINE_DB --scan-id SCAN_ID --payload FILE
PYTHON DB_HELPER resolve-attempt --db PIPELINE_DB --scan-id SCAN_ID --payload FILE
PYTHON DB_HELPER commit-fact --db PIPELINE_DB --scan-id SCAN_ID --payload FILE
PYTHON DB_HELPER commit-finding --db PIPELINE_DB --scan-id SCAN_ID --payload FILE
PYTHON DB_HELPER transition-task --db PIPELINE_DB --scan-id SCAN_ID --stage-run-id STAGE_RUN_ID --task-id TASK_ID --status running|completed|skipped|failed [--reason TEXT]
```

Each configured task starts as `pending`. Start it before its first probe and
finish it only after all of its leads are closed. A directly inapplicable task
may move from `pending` to `skipped`; a failed task requires a reason.

Send exactly one HTTP hop with:

```text
PYTHON HTTP_REQUEST_HELPER request --db PIPELINE_DB --scan-id SCAN_ID --stage-run-id STAGE_RUN_ID --task-id TASK_ID --policy TARGET_POLICY --payload REQUEST.json
```

The request payload contains `method`, `url`, optional string `headers`, optional
UTF-8 `body` (or `body_base64`), and optional `timeout_seconds`. A state-changing
request must also contain exactly one `risk_class`:

- `application_mutation`: ordinary bounded form/API mutation.
- `test_resource_create`: creates disposable data whose captured identifier may
  authorize a later same-task DELETE.
- `test_resource_delete`: deletes only such a cryptographically bound test resource.
- `external_side_effect`: may trigger payment, email, SMS, notification, webhook,
  invitation, or another effect outside the target data plane; requires approval.
- `destructive_or_bulk`: destructive, disruptive, or mass action; always rejected.

Safe methods use `http_probe` implicitly. The helper
validates task state and TargetPolicy, reserves the durable shared request/rate/
concurrency budget, disables proxies and redirects, and returns a JSON response
with `request_id`, `request_fingerprint`, status, sanitized headers, and a
bounded body. Never use another HTTP transport. Treat a 3xx `Location` as a new
candidate and submit it as another guarded request only if needed.

For dual-account IDOR only, replay an eligible successful read-only Recon
transaction with the separate operator-logged-in B identity:

```text
PYTHON HTTP_REQUEST_HELPER replay-observed --db PIPELINE_DB --scan-id SCAN_ID --stage-run-id STAGE_RUN_ID --task-id TASK_ID --policy TARGET_POLICY --source-request-id HTTP_TRANSACTION_ID --target-origin https://approved.example --identity-role identity_b
```

This flow is restricted to a successful, authenticated, non-excluded
GET/HEAD/OPTIONS transaction from the same scan. It preserves the original
object ID and request shape; only the authentication context changes. The
trusted broker binds the B session to one exact origin and injects its local
session path. Never ask the agent to read the session, pass credentials in
arguments, alter the captured request, or use this mode for writes.
`attack_http_requests.identity_role` records the identity used for each
replay. The returned response is bounded and must be compared semantically;
status differences alone do not establish IDOR.

`commit-attempt` fields:

```json
{"task_id":"configured task ID","skill_name":"hunt-example","endpoint_id":"endpoint_id or empty","request_fingerprint":"fingerprint returned by HTTP helper","method":"GET","url":"https://target/path","identity_role":"unauthenticated","payload_variant":"short label","response_status":200,"response_signature":"sha256 digest","outcome":"negative|lead|inconclusive"}
```

`commit-finding` requires `scan_id`, optional `endpoint_id`, `vuln_type`,
`severity`, `title`, `description`, optional CVSS/CWE fields, and a non-empty
`evidence` array. Include the IDs of every supporting open lead in
`lead_attempt_ids`; the helper atomically changes them to `confirmed` and links
them to the finding. It also requires exactly one `reproduction` object:

```json
{"method":"GET","endpoint_template":"/api/items/{id}","injection_location":"path","parameter_name":"id","payload_template":{"id":"<slot:string>"},"required_identity_roles":[],"source_request_ids":["HTTP ledger request ID"],"runtime_contract":{"schema_version":1,"target":{"request":{"path_parameters":{"id":"target-object"}},"assertions":[{"assertion_id":"target-effect","kind":"json_equals","path":["owner_id"],"expected":"other-user"}]},"positive_control":{"request":{"path_parameters":{"id":"owned-object"}},"assertions":[{"assertion_id":"healthy-path","kind":"status_equals","expected":200}]},"negative_control":{"request":{"path_parameters":{"id":"inert-object"}},"assertions":[{"assertion_id":"target-effect","kind":"json_equals","path":["owner_id"],"expected":"other-user"}]}}}
```

For HTTP findings, include `runtime_contract` whenever the target effect can be
expressed with bounded response assertions. Each attempt declares path/query
values, non-secret headers, one JSON or text body, and one to sixteen assertions.
Supported assertion kinds are `status_equals`, `header_equals`, `body_contains`,
`json_equals`, `duration_at_least_ms`, and `duration_at_most_ms`.

For DOM effects, use a `runtime_kind: "browser"` contract. Each target/control
attempt contains a body-free `navigation`, a bounded `wait_ms`, and assertions
using `selector_exists`, `selector_text_contains`, `attribute_equals`,
`url_equals`, or `console_contains`. Selectors and console markers must be
specific to the observed effect; header absence alone is not a browser proof.

For OOB effects, use `runtime_kind: "oob"`. Each attempt contains an HTTP
`trigger`, a `token_template` with exactly one `{nonce}`, the allowed callback
`protocols`, `minimum_callbacks`, and `wait_seconds`. The complete token template
must appear exactly once in the trigger. Validation derives a new nonce from
every attempt ID, arms the observer before sending the policy-checked trigger,
and ignores callbacks with stale tokens or undeclared protocols.

For file-upload effects, use `runtime_kind: "multipart"`. The adapter, not the
contract, generates the boundary and framing headers. A minimal contract is:

```json
{"runtime_kind":"multipart","schema_version":1,"target":{"request":{"query_parameters":{"variant":"target"},"files":[{"name":"file","filename":"fixture.gif","content_type":"image/gif","content":{"artifact_ref":"fixture-gif-v1","length":6,"sha256":"610f5ae4d76e332636a17bd357fd6ce99029316a99d320280d4d77a746bf29e8"}}]},"assertions":[{"assertion_id":"proof","kind":"body_contains","expected":"uploaded"}]},"positive_control":{"request":{"query_parameters":{"variant":"baseline"},"files":[{"name":"file","filename":"fixture.gif","content_type":"image/gif","content":{"artifact_ref":"fixture-gif-v1","length":6,"sha256":"610f5ae4d76e332636a17bd357fd6ce99029316a99d320280d4d77a746bf29e8"}}]},"assertions":[{"assertion_id":"healthy","kind":"status_equals","expected":200}]},"negative_control":{"request":{"query_parameters":{"variant":"inert"},"files":[{"name":"file","filename":"fixture.gif","content_type":"image/gif","content":{"artifact_ref":"fixture-gif-v1","length":6,"sha256":"610f5ae4d76e332636a17bd357fd6ce99029316a99d320280d4d77a746bf29e8"}}]},"assertions":[{"assertion_id":"proof","kind":"body_contains","expected":"uploaded"}]}}
```

Multipart supports the six HTTP assertion kinds listed above. Each attempt has
at most 32 path values, 64 query values, 32 non-sensitive headers, 64 text
fields, 32 files, and 16 assertions; at least one file and one assertion are
required. Names are bounded to 128 characters for form parts, 256 for filenames
and request keys, 3--256 for content types, and 256 for header names. Text field
values are at most 100,000 characters, while header and path/query scalar values
are at most 16,384 characters. Shared HTTP assertion IDs are at most 128
characters and expected strings at most 16,384 characters. Assertion JSON paths
have at most 16 components; string components are nonempty and at most 256
characters, and integer components are nonnegative. `status_equals` accepts only
integer status values 100--599, and duration expectations must be finite
nonnegative numbers. Each binary value and the fully framed multipart body are
at most 1,000,000 bytes.

Multipart assertion evidence requires a complete response body strictly below
200,000 bytes. Reaching exactly 200,000 captured bytes makes response
completeness unknown rather than complete; after dispatch this produces
`outcome_unknown` and is not retried automatically.
One absolute policy timeout includes pacing, connection/TLS, response headers,
and body completion, even when the response continues making progress. Native
I/O is closed on expiry. Trusted injected transports retain their own blocking
I/O cancellation responsibility and cannot return proof after the deadline.
Persisted multipart evidence contains assertion identity and expected/actual
digests, pass flags, response status, elapsed milliseconds, and response payload
digest/length; upload data, response data, and header values are omitted.

For WebSocket effects, use `runtime_kind: "websocket"` with a `ws` or `wss`
endpoint and an ordered frame exchange:

```json
{"runtime_kind":"websocket","schema_version":1,"target":{"endpoint":"ws://127.0.0.1/items","frames":[{"kind":"json","value":{"message":"target"}}],"assertions":[{"assertion_id":"proof","kind":"json_equals","frame_index":0,"path":["message"],"expected":"target"}]},"positive_control":{"endpoint":"ws://127.0.0.1/items","frames":[{"kind":"json","value":{"message":"baseline"}}],"assertions":[{"assertion_id":"healthy","kind":"json_equals","frame_index":0,"path":["message"],"expected":"baseline"}]},"negative_control":{"endpoint":"ws://127.0.0.1/items","frames":[{"kind":"json","value":{"message":"inert"}}],"assertions":[{"assertion_id":"proof","kind":"json_equals","frame_index":0,"path":["message"],"expected":"target"}]}}
```

Outbound frame kinds are `text`, `json`, `binary`, `ping`, and final `close`.
Assertion kinds are exactly `text_contains`, `json_equals`, `binary_sha256`,
`close_code_equals`, `subprotocol_equals`, and `frame_kind_sequence`. Endpoints
and origins are at most 2,048 characters; endpoints may have at most 32
non-sensitive query fields (128-character names and 1,024-character values).
Each attempt has at most 32 non-sensitive handshake headers (256-character
names, 16,384-character values), 16 unique subprotocols of at most 128
characters, 1--32 outbound frames, and 1--16 assertions. A frame, all outbound
frames together, received bytes, and a JSON value are each capped at 1,000,000
bytes; ping data is capped at 125 bytes. Capture is capped at 64 frames,
assertion frame indexes at 63, assertion paths at 16 components of at most 128
characters, assertion IDs at most 128 characters, and a frame-kind sequence at
64 entries. The complete sanitized WebSocket evidence envelope is independently
capped at 8,192 encoded bytes; satisfying the individual frame and assertion
limits does not override that aggregate ceiling. Connection and receive waits
must be positive and no more than 120 seconds, and cannot exceed policy. Outbound
close codes are 1000--1003, 1007--1014, or 3000--4999.
Before connecting, the adapter also reserves a `controls` operation for automatic
Pong, peer-close replies, and cleanup/error close. For an inbound limit of N,
this allowance consumes N+1 request units and (N+1)*131 bytes, including masking
and control-frame overhead. The broker records `request_units` and control
limits durably, prepays their rate slots, and retains the full charge after
completion or failure. Parsed-frame guards enforce the inbound limit before
automatic output and bound outgoing controls to that allowance. Explicit close
is conservatively charged against both its declared frame and control allowance.
Unused reservations are abandoned only if never dispatched; a potentially used
allowance with incomplete session results remains `outcome_unknown`.

For unary gRPC effects, use `runtime_kind: "grpc"`. Supply a packaged protobuf
descriptor-set reference; reflection and inferred descriptors are not allowed:

```json
{"runtime_kind":"grpc","schema_version":1,"target":{"endpoint":"http://127.0.0.1:50051","service":"fixture.Echo","method":"Unary","descriptor":{"artifact_ref":"fixture-echo-v1","length":113,"sha256":"1882df0f4c54a559f89c96f3f72c891728f247bc98a765007ee4986937f2d025"},"message":{"value":"target"},"assertions":[{"assertion_id":"proof","kind":"protobuf_path_equals","path":["value"],"expected":"target"}]},"positive_control":{"endpoint":"http://127.0.0.1:50051","service":"fixture.Echo","method":"Unary","descriptor":{"artifact_ref":"fixture-echo-v1","length":113,"sha256":"1882df0f4c54a559f89c96f3f72c891728f247bc98a765007ee4986937f2d025"},"message":{"value":"baseline"},"assertions":[{"assertion_id":"healthy","kind":"grpc_status_equals","expected":"OK"}]},"negative_control":{"endpoint":"http://127.0.0.1:50051","service":"fixture.Echo","method":"Unary","descriptor":{"artifact_ref":"fixture-echo-v1","length":113,"sha256":"1882df0f4c54a559f89c96f3f72c891728f247bc98a765007ee4986937f2d025"},"message":{"value":"inert"},"assertions":[{"assertion_id":"proof","kind":"protobuf_path_equals","path":["value"],"expected":"target"}]}}
```

gRPC assertion kinds are exactly `grpc_status_equals`,
`protobuf_path_equals`, `trailer_equals`, `error_detail_contains`,
`duration_at_least_ms`, and `duration_at_most_ms`. HTTP transport status and
gRPC status are distinct evidence. The endpoint is an HTTP(S) authority of at
most 2,048 characters; service and method names are at most 256 and 128
characters. Descriptor sets are at most 1,000,000 bytes and 64 files, with
256-character unique filenames. Request JSON is at most 1,000,000 encoded
bytes and 32 levels; serialized request and response limits are independently
1--1,000,000 bytes. Each attempt has at most 32 metadata entries (256-character
names and 16,384-character values, 32,768 bytes total), 16 unique credential
references, 1--16 assertions, and a positive deadline no greater than 120
seconds. Assertion IDs are at most 128 characters, expected strings at most
16,384 characters, captured error details at most 16,384 bytes, paths at most
16 components of at most 128 characters, trailers at most 256 characters, and
initial and trailing response metadata each at most 32 entries and 32,768 bytes
total. Each initial/trailing metadata value is at most 16,384 bytes. The
complete sanitized gRPC evidence envelope is independently capped at 8,192
encoded bytes; the individual message, assertion, and metadata limits do not
override it.
The native adapter accepts proof only after a normally returned, fully captured
OK call. Every `grpc.RpcError`, including genuine peer non-OK statuses, is
`outcome_unknown` with an indeterminate signal: grpcio's public API cannot
reliably distinguish these from local rejection or transport failure. Captured
bodies, metadata, matching status assertions, and diagnostic text do not resolve
that ambiguity. Non-OK status/error-detail assertions remain representable in
contracts but cannot establish proof through this native adapter.

For race effects, use `runtime_kind: "concurrent"`. It releases only HTTP or
multipart child requests at a barrier; this minimal HTTP-child example is:

```json
{"runtime_kind":"concurrent","schema_version":1,"workers":2,"repeat_count":1,"release_strategy":"simultaneous","barrier_timeout_seconds":1,"target":{"request":{"query_parameters":{"variant":"target"}},"member_assertions":[{"assertion_id":"proof","kind":"status_equals","expected":200}],"aggregate_assertions":[{"assertion_id":"successes","kind":"success_count_equals","expected":2}],"start_skew_at_most_ms":100},"positive_control":{"request":{"query_parameters":{"variant":"baseline"}},"member_assertions":[{"assertion_id":"healthy","kind":"status_equals","expected":200}],"aggregate_assertions":[{"assertion_id":"healthy-successes","kind":"success_count_equals","expected":2}],"start_skew_at_most_ms":100},"negative_control":{"request":{"query_parameters":{"variant":"inert"}},"member_assertions":[{"assertion_id":"proof","kind":"status_equals","expected":200}],"aggregate_assertions":[{"assertion_id":"successes","kind":"success_count_equals","expected":2}],"start_skew_at_most_ms":100}}
```

Concurrent member and optional final HTTP assertions use the six HTTP assertion
kinds and the shared HTTP assertion bounds above. An HTTP child or final
verification accepts either `text_body` of at most 100,000 characters or an
encoded `json_body` of at most 100,000 bytes, never both. Aggregate kinds are
exactly `success_count_equals`,
`success_count_at_least`, `distinct_response_digests_at_least`, and
`final_http_assertion_passes`; the last requires one bounded HTTP-only final
verification. Workers are 2--20, repeat count 1--5, and their product is at most
20 and must also be no greater than the active policy concurrency limit. The
complete member product is atomically reserved and released as one group; an
optional final HTTP verification is reserved afterward. The barrier timeout is
positive and at most 30 seconds. One shared absolute deadline, computed as the
minimum of `barrier_timeout_seconds` and the policy timeout, governs reservation
pacing, readiness/barrier waits, member I/O, and final verification. Each attempt
has 1--16 member assertions, at most 8 aggregate assertions, an optional positive
start-skew limit no greater than 30,000 ms, and inherited HTTP/multipart child
bounds. Aggregate counts are 0--20. Each member and final verification requires
a complete response body strictly below 200,000 bytes; reaching exactly 200,000
captured bytes after dispatch produces `outcome_unknown` and is not retried
automatically. WebSocket, gRPC, and recursive concurrent children are rejected.

Binary content is either strict base64 or one opaque `artifact_ref`, never both.
It always declares exact byte length and SHA-256; artifact references are 1--256
characters matching `[A-Za-z0-9][A-Za-z0-9._:-]*`, never filesystem paths.
Inline base64 text is at most 1,333,336 characters and still decodes to no more
than 1,000,000 bytes.
Declare identity roles in `required_identity_roles`; trusted staging binds them
to opaque credential references instead of putting secrets in headers or
metadata. gRPC's optional per-attempt credential references are 1--128
characters in the same opaque alphabet, unique, and limited to 16; they must
already be present in the staged case.

Every multipart request and unary gRPC call, each WebSocket handshake, declared
outbound frame and bounded control allowance, every concurrent member, and any
concurrent final HTTP verification is durably reserved before network dispatch.
HTTP and protocol operations atomically share request counts and the latest
scheduled rate slot, including completed history. Positive or negative proof
may cite only completed operation rows owned by the current attempt; failed or
unknown rows may appear only in non-proof audit evidence. A dispatched or
`running` operation with an unknowable result becomes `outcome_unknown` and is
never retried automatically; only an undispatched reservation may be abandoned
safely.

These contracts do not admit raw TCP or HTTP-smuggling bytes, caller-selected
multipart boundaries, Socket.IO framing, gRPC streaming or reflection,
WebSocket/gRPC concurrent children, arbitrary local paths, shell commands,
Python callbacks, or plaintext credentials.

The target assertions describe the vulnerability effect and should pass when it
is reproduced. The positive-control assertions describe a healthy transport,
identity, and parser path and should pass. Negative-control assertions also
describe the vulnerability effect, so they should fail for the inert input. Do
not write an "effect is absent" assertion for the negative control because a
passing assertion means `signal_observed=true`.

Do not place credentials in runtime headers. Declare `required_identity_roles`
and let the trusted Validation runtime resolve their opaque references. Browser,
OOB, and multi-step findings may omit this HTTP-only contract until their
dedicated runtime contract is available.

`reproduction` may also include one immutable `development_contract` when
Attack knows the exact prerequisite request needed to recover from an objective
Validation blocker:

```json
{"schema_version":1,"actions":[{"contract_id":"refresh-current-role","action_type":"refresh_current_role_credential","blocker_axis":"identity_auth","endpoint_template":"/session/refresh","method":"POST","risk_class":"application_mutation","request":{},"assertions":[{"assertion_id":"session-refreshed","kind":"json_equals","path":["refreshed"],"expected":true}],"credential_roles":["current-user"]}]}
```

Each contract contains one or two actions and must match the selected Hunt
Skill's Validation profile allowlist. Its endpoint is a literal same-origin
path; put fixed query values in `request.query_parameters`. `GET`, `HEAD`, and
`OPTIONS` require `risk_class: "http_probe"`; `POST`, `PUT`, and `PATCH` require
`application_mutation` or `test_resource_create`. `DELETE`, absolute URLs,
redirect following, path traversal, high-impact paths, sensitive headers, and
status-only success assertions are rejected. Credential roles must be declared
in `required_identity_roles`; store no secret value. Omit the contract when the
exact request or a target-specific success marker is unknown. Validation then
fails the development action closed instead of asking the LLM to invent one.

`reproduction` may additionally include `impact_development_contract` for an
exact profile-declared impact path. These actions are limited to `GET`, `HEAD`,
or `OPTIONS`, must reuse the reproduction endpoint template and method, and
must include a non-status assertion for the expected impact signal:

```json
{"schema_version":1,"actions":[{"contract_id":"cross-role-object-7","path_id":"cross-role-object-access","endpoint_template":"/api/items/{id}","method":"GET","request":{"path_parameters":{"id":"other-test-object"}},"assertions":[{"assertion_id":"other-owner","kind":"json_equals","path":["owner_id"],"expected":"other-test-user"}],"credential_roles":["current-user"]}]}
```

The path must exist in the selected Validation Skill contract with
`execution_owner: validation`. Omit this contract unless Attack has already
identified the exact test resource, declared identity role, and target-specific
assertion. The Impact Development Agent only judges prerequisites; Python sends
the immutable request and evaluates its assertions.

The native Validation runtime resolves `env://NAME` references and lazily uses
Python keyring for `keyring://SERVICE/ACCOUNT`. Both secrets contain a JSON
object whose keys and values are the HTTP credential headers, for example
`{"Authorization":"Bearer ..."}`. An application may configure a trusted
`vault` scheme backend when its Vault address, namespace, KV version, and auth
method are known. An unconfigured backend is unavailable before any target
request. Resolved values exist only in memory at dispatch; the request ledger
sanitizes sensitive header values.

For OOB runtime contracts, the native process may configure a service-neutral
observer with `AIDAST_OOB_OBSERVER_CONFIG`:

```json
{"arm_url":"https://observer.example/v1/arm","poll_url":"https://observer.example/v1/events","auth_env":"AIDAST_OOB_AUTH_HEADERS"}
```

The auth environment variable contains the same JSON header-map format. The
arm endpoint accepts `{"token":"..."}` and returns `{"cursor":123}`. The poll
endpoint receives `token`, `after`, and `wait_seconds` query parameters and
returns `{"events":[{"cursor":124,"token":"...","protocol":"dns"}]}`.
Only events after the armed cursor can reach Validation evidence.

Every source request must be completed, share the supporting attempt's task and
fingerprint, and have one non-null TargetPolicy digest. Each evidence item contains role, method, URL, redacted
request headers/body, response status, redacted response headers/body, and
elapsed ms.

An open lead that does not meet the active Hunt Skill's confirmation gate must
be closed with `resolve-attempt` and a payload such as:

```json
{"attempt_id":"attempt_id","resolution":"rejected|inconclusive","reason":"bounded evidence-based reason"}
```

Never mark a confirmed behavior rejected merely to pass the completion gate.

The helper validates completed-scan ownership and endpoint membership and uses
parameterized transactions. It contains no HTTP or vulnerability logic.
