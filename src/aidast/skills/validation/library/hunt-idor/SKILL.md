---
name: aidast-validation-idor
description: Interpret bounded hunt-idor replay evidence and impact without authorizing requests or choosing the final status.
---

# hunt-idor validation

Apply this guidance only to the staged BlindCase, its immutable contract, and fresh observations. Treat the Attack Skill as mechanism context, not execution authority.

## Proof standard

a low-privilege identity receives the other test identity object or state transition

Require the declared positive control to prove the signal channel is operational and the inert negative control to stay clear. Do not infer reproduction from status codes, hashes, timing noise, or the Attack claim alone.

## Impact interpretation

- Boundary: identify the exact unauthenticated, identity, role, tenant, or administrator boundary crossed
- Sensitivity: identify only protected fields or committed actions observed in the fresh response
- Actor requirements: score the lowest role and setup that reproduced the unauthorized access

Cite only evidence from the current Validation case for every impact score.

## Impact expansion

When impact is underpowered, select only a path declared in `contract.json`; never invent a path, prerequisite, request, credential, or payload.

### `cross-role-object-access`

Use this path only for the `boundary` gap when its prerequisites are evidenced.

Prerequisites:
- A second low-privilege test identity
- A test object owned by that identity

Recommended interpretation:
- Replay the same object reference from the first low-privilege identity

Expected signal kind: `other_identity_object_returned`. Execution owner: `validation`.

### `sensitive-object-field`

Use this path only for the `sensitivity` gap when its prerequisites are evidenced.

Prerequisites:
- A test object containing a unique non-secret marker

Recommended interpretation:
- Check only the declared response field for the marker

Expected signal kind: `unique_marker_returned`. Execution owner: `validation`.
