"""Case-based reports plus persisted legacy report compatibility."""

from .case_runtime import (
    case_report_status,
    prepare_case_report,
    read_verified_case,
    record_case_report,
)
from .legacy_models import CitedText, ReportDraft, validate_draft
from .legacy_render import render_report
from .legacy_runtime import PLATFORMS
from .legacy_runtime import ReportAgent, ReportError, ReportWriter
from .legacy_runtime import prepare_report, record_report, report_status
from .models import CitedText as CaseCitedText
from .models import ReportDraft as CaseReportDraft
from .models import validate_draft as validate_case_draft
from .render import render_report as render_case_report
from .runtime import ReportAgent as CaseReportAgent
from .runtime import ReportError as CaseReportError
from .runtime import ReportWriter as CaseReportWriter

LegacyReportAgent = ReportAgent
LegacyCitedText = CitedText
LegacyReportDraft = ReportDraft
LegacyReportError = ReportError
LegacyReportWriter = ReportWriter
prepare_legacy_report = prepare_report
record_legacy_report = record_report
legacy_report_status = report_status
LEGACY_PLATFORMS = PLATFORMS
render_legacy_report = render_report
validate_legacy_draft = validate_draft

__all__ = [
    "CitedText",
    "CaseReportAgent",
    "CaseCitedText",
    "CaseReportDraft",
    "CaseReportError",
    "CaseReportWriter",
    "LEGACY_PLATFORMS",
    "LegacyCitedText",
    "LegacyReportAgent",
    "LegacyReportDraft",
    "LegacyReportError",
    "LegacyReportWriter",
    "PLATFORMS",
    "ReportAgent",
    "ReportDraft",
    "ReportError",
    "ReportWriter",
    "case_report_status",
    "legacy_report_status",
    "prepare_case_report",
    "prepare_legacy_report",
    "prepare_report",
    "read_verified_case",
    "record_case_report",
    "record_legacy_report",
    "record_report",
    "render_legacy_report",
    "render_case_report",
    "render_report",
    "report_status",
    "validate_draft",
    "validate_case_draft",
    "validate_legacy_draft",
]
