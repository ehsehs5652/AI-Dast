---
name: aidast-validation-ldap
description: Interpret bounded hunt-ldap replay evidence and impact without authorizing requests or choosing the final status.
---

# hunt-ldap validation

Apply this guidance only to the staged BlindCase, its immutable contract, and fresh observations. Treat the Attack Skill as mechanism context, not execution authority.

## Proof standard

crafted LDAP input produces a directory-specific parsing signal or unauthorized result-set change

Require the declared positive control to prove the signal channel is operational and the inert negative control to stay clear. Do not infer reproduction from status codes, hashes, timing noise, or the Attack claim alone.

## Impact interpretation

- Boundary: credit a boundary only when the fresh result changes access or execution beyond an error alone
- Sensitivity: distinguish parser disclosure from data access, file read, query control, or code execution
- Actor requirements: score the minimum reachable input surface and authentication role

Cite only evidence from the current Validation case for every impact score.

## Impact expansion

This profile declares no automatic impact-expansion path. Do not invent one; leave the result UNDERPOWERED when the observed impact is insufficient.
