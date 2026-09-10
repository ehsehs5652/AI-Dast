"""Offline, validation-bound reports for HackerOne, Bugcrowd and Intigriti."""

from .models import CitedText, ReportDraft, validate_draft
from .render import render_report
from .runtime import (
    PLATFORMS, ReportAgent, ReportError, ReportWriter,
    prepare_report, record_report, report_status,
)

__all__ = ["CitedText", "ReportDraft", "validate_draft", "render_report", "PLATFORMS",
           "ReportAgent", "ReportError", "ReportWriter", "prepare_report", "record_report", "report_status"]
