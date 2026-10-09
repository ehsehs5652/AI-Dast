# Vendored Strix engine

AI DAST vendors the Strix Python engine under `src/aidast/recon/strix_engine/`.
The vendored source is adapted to the `aidast.recon.strix_engine` import
namespace and is included in the AI DAST package. The `reference/strix/`
checkout is not needed at runtime.

Upstream: Strix 1.6.2, Apache License 2.0. The upstream license is retained at
`src/aidast/recon/strix_engine/LICENSE`. Local modifications include import
namespace relocation and AIDAST-specific MITM capture integration. Compare
against `reference/strix/` only for development; runtime code must not import
from that directory.

The Recon runtime still needs its Python dependencies (install with the
`recon-engine` extra), a configured LLM provider/login, and the sandbox image.
Vendoring removes the runtime dependency on the reference source checkout; it
does not remove those operational prerequisites.
