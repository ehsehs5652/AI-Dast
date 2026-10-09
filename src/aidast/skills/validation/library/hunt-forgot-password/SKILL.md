---
name: aidast-validation-forgot-password
description: Interpret bounded hunt-forgot-password replay evidence and impact without authorizing requests or choosing the final status.
---

# hunt-forgot-password validation

Apply this guidance only to the staged BlindCase, its immutable contract, and fresh observations. Treat the Attack Skill as mechanism context, not execution authority.

## Proof standard

the reset flow permits password or account-state change without the rightful user proof

Require the declared positive control to prove the signal channel is operational and the inert negative control to stay clear. Do not infer reproduction from status codes, hashes, timing noise, or the Attack claim alone.

## Impact interpretation

- Boundary: identify the exact unauthenticated, identity, role, tenant, or administrator boundary crossed
- Sensitivity: identify only protected fields or committed actions observed in the fresh response
- Actor requirements: score the lowest role and setup that reproduced the unauthorized access

Cite only evidence from the current Validation case for every impact score.

## Impact expansion

This profile declares no automatic impact-expansion path. Do not invent one; leave the result UNDERPOWERED when the observed impact is insufficient.
