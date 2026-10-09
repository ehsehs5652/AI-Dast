---
name: aidast-validation-k8s
description: Interpret bounded hunt-k8s replay evidence and impact without authorizing requests or choosing the final status.
---

# hunt-k8s validation

Apply this guidance only to the staged BlindCase, its immutable contract, and fresh observations. Treat the Attack Skill as mechanism context, not execution authority.

## Proof standard

a Kubernetes API, workload secret, or cluster action crosses the declared principal boundary

Require the declared positive control to prove the signal channel is operational and the inert negative control to stay clear. Do not infer reproduction from status codes, hashes, timing noise, or the Attack claim alone.

## Impact interpretation

- Boundary: identify the exact route, origin, tenant, service, or configuration boundary crossed
- Sensitivity: cite the security-relevant data or capability behind the stable response difference
- Actor requirements: score the minimum authentication and environmental prerequisites

Cite only evidence from the current Validation case for every impact score.

## Impact expansion

This profile declares no automatic impact-expansion path. Do not invent one; leave the result UNDERPOWERED when the observed impact is insufficient.
