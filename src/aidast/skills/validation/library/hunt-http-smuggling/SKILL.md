---
name: aidast-validation-http-smuggling
description: Interpret bounded hunt-http-smuggling replay evidence and impact without authorizing requests or choosing the final status.
---

# hunt-http-smuggling validation

Apply this guidance only to the staged BlindCase, its immutable contract, and fresh observations. Treat the Attack Skill as mechanism context, not execution authority.

## Proof standard

paired requests produce a stable downstream parsing or response-queue desynchronization signal

Require the declared positive control to prove the signal channel is operational and the inert negative control to stay clear. Do not infer reproduction from status codes, hashes, timing noise, or the Attack claim alone.

## Impact interpretation

- Boundary: credit a boundary only when controlled timing or concurrency changes a protected outcome
- Sensitivity: cite the resulting data, state, cache, or protocol effect rather than latency alone
- Actor requirements: score request count, concurrency, authentication, and timing precision required

Cite only evidence from the current Validation case for every impact score.

## Impact expansion

This profile declares no automatic impact-expansion path. Do not invent one; leave the result UNDERPOWERED when the observed impact is insufficient.
