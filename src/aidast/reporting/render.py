"""Pure Markdown renderer for three local platform templates."""

from __future__ import annotations

import html
import re

from .models import CitedText, ReportDraft


def _plain(value: str) -> str:
    # Captured content is text, never an HTML element, image or clickable URL.
    value = html.escape(value, quote=False)
    return re.sub(r"([\\`*_{}\[\]()#+.!|~-])", r"\\\1", value)


def _cited(value: CitedText) -> str:
    return _plain(value.text) + "\n\nEvidence: " + ", ".join(f"`{item}`" for item in value.evidence_ids)


def render_report(draft: ReportDraft) -> str:
    blocks = [f"# {_plain(draft.title.text)}", "Local draft — not submitted.",
              f"Platform: {draft.platform}\n\nValidation: `{draft.validation_id}`",
              "Title evidence: " + ", ".join(f"`{item}`" for item in draft.title.evidence_ids)]

    def section(heading: str, content: CitedText | str | None) -> None:
        if content is not None:
            blocks.extend([f"## {heading}", _cited(content) if isinstance(content, CitedText) else content])

    section("Target" if draft.platform == "bugcrowd" else "Asset", draft.asset)
    section("Vulnerability Type" if draft.platform == "intigriti" else "Weakness", draft.weakness)
    section("VRT Category", draft.vrt_category)
    section("Technical Severity" if draft.platform == "bugcrowd" else "Severity", draft.severity)
    section("CVSS Vector", draft.cvss_vector)
    section("Summary" if draft.platform == "hackerone" else "Description", draft.summary)
    if draft.prerequisites:
        section("Prerequisites", "\n\n".join(_cited(item) for item in draft.prerequisites))
    section("Steps to Reproduce", "\n\n".join(
        f"{number}. " + _cited(item).replace("\n", "\n   ")
        for number, item in enumerate(draft.steps_to_reproduce, 1)))
    section("Expected Behavior", draft.expected_behavior)
    section("Actual Behavior", draft.actual_behavior)
    section("Demonstrated Impact" if draft.platform == "bugcrowd" else "Impact", draft.impact)
    section("Recommended Solution" if draft.platform == "intigriti" else "Recommended Fix",
            None if draft.remediation is None else _plain(draft.remediation))
    if draft.attachment_evidence_ids:
        section("Supporting Materials" if draft.platform == "hackerone" else "Attachments",
                "Evidence references only; files are not uploaded.\n\n" + "\n".join(
                    f"- `{item}`" for item in draft.attachment_evidence_ids))
    blocks.extend(["## Source Binding", f"Context SHA-256: `{draft.source_context_sha256}`"])
    return "\n\n".join(blocks) + "\n"
