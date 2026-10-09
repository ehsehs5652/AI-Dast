---
name: endpoint_inventory
description: General web Recon workflow for turning links, browser routes, JavaScript strings, API descriptions, and crawler output into evidence-backed endpoint inventory without confusing inferred candidates with observed traffic.
---

# Evidence-backed endpoint inventory

Use this workflow for any in-scope web application. It is framework- and site-agnostic; derive routes, methods, and parameters from the current target's evidence rather than a target-specific list.

## Keep evidence classes distinct

For every candidate, preserve its source and confidence:

- **Observed:** an in-scope request/response exists in the approved MITM journal. This may be persisted as a runtime endpoint.
- **Disclosed:** a link, form, client bundle, API description, robots/sitemap document, or browser route reveals a candidate, but no request has yet verified it.
- **Inferred:** a route template or method/parameter shape was derived from code or neighboring observations, but no concrete request established it.
- **Rejected/unreachable:** a bounded, scope-approved validation request returned a clear negative result, or the request could not be made. Keep the result and reason; do not silently erase the lead.

Do not describe a disclosed or inferred route as observed, and do not assume every string in a minified bundle is an active server route. Keep request/response evidence separate from route templates.

## Build candidates from multiple independent sources

Start with the approved seed and gather the links, forms, redirects, script URLs, robots.txt/sitemap references, API-description documents, and routes surfaced by the browser. Inspect first-party JavaScript and lazy-loaded chunks when the rendered UI or observed API surface is sparse. Extract route templates, method hints, and parameter names with their source locations; do not invent parameter values.

Use a browser and at least one available non-browser crawler for web pages. Katana and Gospider are complementary options; select tools and order based on the target and evidence. Make sure the exact approved start URL is passed, the process exits successfully, and output is parsed in the format actually produced. A successful exit with zero URLs is not evidence of coverage.

Compare each crawler's URLs with the approved MITM capture journal. If the crawler output is empty or its requests are missing from the journal, check its seed, proxy environment/explicit proxy option, TLS result, output format, and whether the application returned HTML or a challenge/error page. Then retry with a complementary source or browser route discovery. Never bypass the Scope-enforcing proxy to obtain results.

## Validate disclosed candidates safely

Before requesting a candidate, resolve it against the observed in-scope base URL and check the final scheme, host, port, and path against the authoritative Scope. The proxy remains the enforcement boundary; a link or API description cannot expand Scope.

For a candidate that is clearly read-only and has a GET representation, issue a low-impact request through the proxy and inspect the captured status, content type, response shape, redirect destination, and whether it is an application fallback. HEAD or OPTIONS may be used when appropriate, but do not assume they are supported or equivalent to GET. Batch only a bounded set of distinct, evidence-derived candidates; avoid repeated retries and brute-force path dictionaries.

HTTP method and Scope permission alone do not prove that an application action is authorized. Scope determines the network boundary and explicitly prohibited methods; it is not blanket approval for every business action. Some applications implement state changes through GET, so classify semantics, not just verbs.

- Passive and clearly read-only discovery may proceed when in Scope.
- A low-impact state change may proceed only when an explicit Recon opt-in covers that action class, using a disposable self-owned account and synthetic data. A single opt-in must not be generalized to unrelated actions.
- Checkout, payment, transfers, deletion, privilege/account-security changes (including 2FA setup/verification/disable), password changes, and export/retrieval of sensitive user data require explicit action-specific operator approval in addition to Scope and method permission. If the current run has no such approval mechanism, do not execute them.

### Explicit isolated-lab expansion

When the operator explicitly starts Recon with `--allow-lab-state-changing-discovery`, that flag is the action-specific approval for endpoint-discovery requests on the exact loopback target only. Runtime validation rejects non-loopback targets and wildcard assets. In this mode:

- After creating one disposable account and logging in, reconcile the disclosed route/method inventory against captured requests.
- For each distinct first-party/UI-disclosed state-changing operation, make at most one request using the observed method and request shape, synthetic values, and only records owned by the disposable account. This includes account-security and export operations on that local lab account.
- Do not brute-force paths/IDs, fuzz inputs, access another identity, contact external payment providers, or delete the account or pre-existing data. `DELETE` is limited to cleanup of a disposable record created in the same run.
- If an operation needs a prerequisite not safely available from observed UI/API evidence, preserve it as disclosed/unverified with that prerequisite rather than inventing identifiers or repeating mutations.

This exception does not apply to public or private program targets, even when their Scope lists the HTTP method as allowed.

The account-registration-only option authorizes only the specified one-time disposable registration/login flow; it does not authorize unrelated forms, data exports, security setting changes, or transactions. Without the isolated-lab expansion above, do not send POST/PUT/PATCH/DELETE bodies, click submit controls, or use example/synthetic identifiers to force a state change without the required approval. Preserve method, body-schema, parameter evidence, source, and the reason it was not executed as **disclosed/inferred**, and continue independent read-only discovery. A Scope prohibition always wins; if the Scope is ambiguous, do not perform the action.

For identifier templates such as `/items/{id}`, only substitute an identifier already observed in an in-scope page or response, and only for a read-only operation. Do not enumerate ID ranges. Record the concrete request and the template association separately.

## Distinguish real endpoints from fallback and errors

An HTTP 200 is not by itself proof that a route exists. Compare candidate responses with the target's observed not-found/fallback behavior using status, content type, redirect chain, and a compact body fingerprint. If a candidate is indistinguishable from the SPA shell, generic error page, or catch-all route, keep it as unconfirmed rather than promoting it to an observed functional endpoint. A 401/403 response is still an observed endpoint when the request reached the application; record the auth state and do not relabel it as a transport failure.

Normalize only for grouping. Preserve the original URL, method, query parameter names, response metadata, and source so normalization cannot hide distinct operations or turn placeholders into claimed observations.

## Close the coverage loop before finishing

For each source, report whether it produced candidates and how many were actually observed in the proxy journal. Reconcile browser routes, crawler URLs, first-party JS/API candidates, and captured requests. For each unobserved candidate family, state one reason: not exercised, state-changing and intentionally left unexecuted, blocked by Scope, unreachable/failed tool, ambiguous fallback, or unsupported/unconfirmed. Verify that captured requests were imported into the scan's endpoint inventory; if capture contains requests but the persisted inventory does not, report a capture-to-inventory gap rather than claiming completion.

At finish, summarize counts separately for observed requests/endpoints, disclosed or inferred candidates, safely rejected/unreachable candidates, and intentionally unexecuted state-changing operations. Include the evidence source and remaining gaps. Never inflate the observed endpoint total with static strings or templates.
