# Claude-BugHunter source attribution

The supplied local `attack` bundle identifies Claude-BugHunter at commit
`e49b9da698bfe830302f0ae49ea02e41cc5cf876` as its upstream.
`LICENSE`, `CREDITS.md`, and `SOURCE.json` are preserved verbatim from
that bundle's `vendor/` directory. They describe the source bundle and its
upstream, including material beyond the scope of this project.
In particular, the historical adaptation statement in `SOURCE.json`
does not describe this project's implementation.

`inventory.json` records SHA-256 hashes measured from all 60 supplied
`SKILL.md` files: 59 under `library/` and one under `controller/`.
Upstream byte identity and authorship of the local controller have not been
independently verified. The inventory records local provenance, not a claim
that all 60 files are unmodified upstream files.

AI-Dast includes only the 59 library entries' identifiers, locally written
titles, broad reference categories, hashes, and local evidence-tag mappings
in `src/aidast/skills/attack/catalog/index.json`.
The source playbooks, controller, SQL scripts, commands, and payloads are not
redistributed or loaded. The original license and community attribution are
retained for provenance.

Every catalog entry is disabled and restricted to metadata. A signal match
suggests a reference topic for human evidence review; it is not a vulnerability
finding, permission to test, or a request to execute a playbook. An empty mapping
means that the current evidence taxonomy does not justify automatic routing.
Mappings were authored locally and are not extracted executable source guidance.

The upstream repository identified by the supplied bundle is
<https://github.com/elementalsouls/Claude-BugHunter>.
