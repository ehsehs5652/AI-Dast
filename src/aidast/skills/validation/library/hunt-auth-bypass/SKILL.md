---
name: aidast-validation-auth-bypass
description: Interpret bounded hunt-auth-bypass replay evidence and impact without authorizing requests or choosing the final status.
---

# hunt-auth-bypass validation

Apply this guidance only to the staged BlindCase, its immutable contract, and fresh observations. Treat the Attack Skill as mechanism context, not execution authority.

## Proof standard

a protected operation succeeds without its required authentication state

Require the declared positive control to prove the signal channel is operational and the inert negative control to stay clear. Do not infer reproduction from status codes, hashes, timing noise, or the Attack claim alone.

## Impact interpretation

- Boundary: identify the exact unauthenticated, identity, role, tenant, or administrator boundary crossed
- Sensitivity: identify only protected fields or committed actions observed in the fresh response
- Actor requirements: score the lowest role and setup that reproduced the unauthorized access

Cite only evidence from the current Validation case for every impact score.

## Impact expansion

This profile declares no automatic impact-expansion path. Do not invent one; leave the result UNDERPOWERED when the observed impact is insufficient.
