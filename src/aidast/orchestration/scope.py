from __future__ import annotations

import hashlib
import errno
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Protocol
from uuid import uuid4

from pydantic import ValidationError

from aidast.scope.models import (
    CaptureReason,
    CaptureStatus,
    ProgramPage,
    ScopeAnalysis,
    ScopeApproval,
    ScopeDocument,
    ScopeManifest,
)


class CoordinatorError(RuntimeError):
    pass


class ScopeCollector(Protocol):
    def collect_scope(self, program_url: str) -> tuple[ProgramPage, ScopeAnalysis]: ...

    def interpret_captured_scope(self, page: ProgramPage) -> ScopeAnalysis: ...


class ProgramPageReader(Protocol):
    def read(self, url: str) -> ProgramPage: ...


class ScopeCoordinator:
    def __init__(self, output_dir: Path | str = "Scope") -> None:
        # tempfile.mkdtemp() returns an absolute path.  Keep the publication
        # destination absolute as well: on WSL/Windows-mounted workspaces an
        # absolute source plus a relative destination can otherwise be
        # classified as a cross-device rename even though both names resolve
        # to the same mounted filesystem.
        self.output_dir = Path(output_dir).resolve(strict=False)

    def collect(
        self,
        program_url: str,
        *,
        main_agent: ScopeCollector,
        fallback_reader: ProgramPageReader | None = None,
        approved_by: str,
        review: Callable[[Path], bool],
    ) -> ScopeDocument | None:
        if self.output_dir.exists():
            raise CoordinatorError(
                f"scope output already exists: {self.output_dir}; "
                "move or remove it before collecting a new scope"
            )
        approved_by = approved_by.strip()
        if not approved_by:
            raise CoordinatorError("approved_by must not be blank")

        page, analysis = main_agent.collect_scope(program_url)
        if (
            page.capture_reason is CaptureReason.JAVASCRIPT_RENDER_INCOMPLETE
            and fallback_reader is not None
        ):
            fallback_page = fallback_reader.read(program_url)
            if (
                fallback_page.capture_status is CaptureStatus.COMPLETE
                or (
                    page.capture_status is CaptureStatus.BLOCKED
                    and fallback_page.capture_status is CaptureStatus.PARTIAL
                )
            ):
                page = fallback_page
                analysis = main_agent.interpret_captured_scope(page)
        if page.capture_status is CaptureStatus.BLOCKED:
            raise CoordinatorError(
                "program page access was blocked; no Scope.md was generated"
            )
        if page.capture_status is not CaptureStatus.COMPLETE:
            raise CoordinatorError(
                f"program page capture is incomplete "
                f"({page.capture_reason.value}); no Scope.md was generated"
            )
        document = ScopeDocument(
            scope_id=f"scope_{uuid4().hex}",
            created_at=datetime.now(timezone.utc),
            source=page,
            analysis=analysis,
        )
        staging = self._create_scope_draft(document)
        try:
            if not review(staging / "Scope.md"):
                return None
            self._publish_scope(staging, document, approved_by)
            return document
        finally:
            shutil.rmtree(staging, ignore_errors=True)

    def verify_approval(self) -> ScopeApproval:
        approval, _, _ = self._load_verified_snapshot()
        return approval

    def load_approved_scope(self) -> tuple[ScopeDocument, str]:
        _, document, markdown = self._load_verified_snapshot()
        return document, markdown

    def _load_verified_snapshot(
        self,
    ) -> tuple[ScopeApproval, ScopeDocument, str]:
        paths = {
            "json": self.output_dir / "Scope.json",
            "markdown": self.output_dir / "Scope.md",
            "manifest": self.output_dir / "Manifest.json",
            "approval": self.output_dir / "Approval.json",
        }
        try:
            content = {name: path.read_bytes() for name, path in paths.items()}
        except OSError as exc:
            raise CoordinatorError(
                f"failed to read approved Scope artifact: {exc.filename or exc}"
            ) from exc

        try:
            manifest = ScopeManifest.model_validate_json(content["manifest"])
            document = ScopeDocument.model_validate_json(content["json"])
            approval = ScopeApproval.model_validate_json(content["approval"])
            markdown = content["markdown"].decode("utf-8")
        except (UnicodeError, ValidationError, ValueError) as exc:
            raise CoordinatorError(f"invalid approved Scope artifact: {exc}") from exc

        json_hash = self._sha256(content["json"])
        markdown_hash = self._sha256(content["markdown"])
        if json_hash != manifest.scope_json_sha256:
            raise CoordinatorError("Scope.json has changed since generation")
        if markdown_hash != manifest.scope_markdown_sha256:
            raise CoordinatorError("Scope.md has changed since generation")
        if document.scope_id != manifest.scope_id:
            raise CoordinatorError("scope document and manifest IDs do not match")
        if approval.scope_id != manifest.scope_id:
            raise CoordinatorError("approval and manifest IDs do not match")
        if (
            approval.scope_json_sha256 != manifest.scope_json_sha256
            or approval.scope_markdown_sha256 != manifest.scope_markdown_sha256
        ):
            raise CoordinatorError("scope files have changed since approval")
        return approval, document, markdown

    def _create_scope_draft(self, document: ScopeDocument) -> Path:
        parent = self.output_dir.parent
        parent.mkdir(parents=True, exist_ok=True)
        staging = Path(
            tempfile.mkdtemp(prefix=f".{self.output_dir.name}-", dir=str(parent))
        )
        try:
            scope_json = document.model_dump_json(indent=2).encode("utf-8") + b"\n"
            scope_markdown = self._render_markdown(document).encode("utf-8")
            (staging / "Scope.json").write_bytes(scope_json)
            (staging / "Scope.md").write_bytes(scope_markdown)

            manifest = ScopeManifest(
                scope_id=document.scope_id,
                generated_at=datetime.now(timezone.utc),
                scope_json_sha256=self._sha256(scope_json),
                scope_markdown_sha256=self._sha256(scope_markdown),
            )
            (staging / "Manifest.json").write_text(
                manifest.model_dump_json(indent=2) + "\n",
                encoding="utf-8",
            )
            return staging
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise

    def _publish_scope(
        self, staging: Path, document: ScopeDocument, approved_by: str
    ) -> None:
        if document.source.capture_status is not CaptureStatus.COMPLETE:
            raise CoordinatorError("a partial scope capture cannot be approved")
        if self.output_dir.exists():
            raise CoordinatorError(
                f"scope output already exists: {self.output_dir}; "
                "the approved draft was not published"
            )

        manifest = self._load_model(staging / "Manifest.json", ScopeManifest)
        self._verify_content_hashes(
            manifest,
            {
                "json": staging / "Scope.json",
                "markdown": staging / "Scope.md",
            },
        )
        approval = ScopeApproval(
            scope_id=document.scope_id,
            approved_by=approved_by,
            approved_at=datetime.now(timezone.utc),
            scope_json_sha256=manifest.scope_json_sha256,
            scope_markdown_sha256=manifest.scope_markdown_sha256,
        )
        approval_path = staging / "Approval.json"
        approval_path.write_text(
            approval.model_dump_json(indent=2) + "\n",
            encoding="utf-8",
        )
        approval_path.chmod(0o600)
        try:
            os.replace(staging, self.output_dir)
        except OSError as exc:
            if exc.errno != errno.EXDEV:
                raise
            self._publish_cross_device(staging)

    def _publish_cross_device(self, staging: Path) -> None:
        """Publish through a sibling copy when rename(2) reports EXDEV."""
        sibling = self.output_dir.parent / (
            f".{self.output_dir.name}-publish-{uuid4().hex}"
        )
        try:
            shutil.copytree(staging, sibling, copy_function=shutil.copy2)
            os.replace(sibling, self.output_dir)
        finally:
            shutil.rmtree(sibling, ignore_errors=True)

    @staticmethod
    def _verify_content_hashes(
        manifest: ScopeManifest, paths: dict[str, Path]
    ) -> None:
        json_hash = ScopeCoordinator._sha256(paths["json"].read_bytes())
        markdown_hash = ScopeCoordinator._sha256(paths["markdown"].read_bytes())
        if json_hash != manifest.scope_json_sha256:
            raise CoordinatorError("Scope.json has changed since generation")
        if markdown_hash != manifest.scope_markdown_sha256:
            raise CoordinatorError("Scope.md has changed since generation")

    @staticmethod
    def _load_model(path: Path, model_type):
        if not path.is_file():
            raise CoordinatorError(f"required file does not exist: {path}")
        try:
            return model_type.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValidationError, ValueError) as exc:
            raise CoordinatorError(f"invalid {path.name}: {exc}") from exc

    @staticmethod
    def _sha256(content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()

    @staticmethod
    def _clean(value: str) -> str:
        return (
            " ".join(value.split())
            .replace("\\", "\\\\")
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("|", "\\|")
            .replace("`", "\\`")
            .replace("*", "\\*")
            .replace("_", "\\_")
            .replace("[", "\\[")
            .replace("]", "\\]")
        )

    @classmethod
    def _render_markdown(cls, document: ScopeDocument) -> str:
        analysis = document.analysis
        lines = [
            f"# Scope: {cls._clean(analysis.program_name)}",
            "",
            f"> Source: {document.source.final_url}",
            f"> Captured at: {document.source.captured_at.isoformat()}",
            f"> Scope ID: `{document.scope_id}`",
            "",
            "## Program summary",
            "",
            cls._clean(analysis.program_description) or "명시되지 않음.",
            "",
            "## In-scope assets",
            "",
        ]
        lines.extend(cls._render_asset_table(analysis.in_scope_assets))
        lines.extend(["", "## Out-of-scope assets", ""])
        lines.extend(cls._render_asset_table(analysis.out_of_scope_assets))
        lines.extend(cls._render_list_section("Allowed activities", analysis.allowed_activities))
        lines.extend(
            cls._render_list_section("Prohibited activities", analysis.prohibited_activities)
        )
        lines.extend(
            cls._render_list_section(
                "Submission requirements", analysis.submission_requirements
            )
        )
        lines.extend(
            cls._render_list_section(
                "Operational constraints", analysis.operational_constraints
            )
        )
        lines.extend(["", "## Safe harbor", ""])
        lines.append(cls._clean(analysis.safe_harbor) or "명시되지 않음.")
        lines.extend(cls._render_list_section("Ambiguities requiring review", analysis.ambiguities))
        lines.extend(["", "## Source evidence", ""])
        if analysis.source_evidence:
            for evidence in analysis.source_evidence:
                lines.append(
                    f"- **{cls._clean(evidence.section)}:** "
                    f"“{cls._clean(evidence.quote)}”"
                )
        else:
            lines.append("- 제공된 근거 없음.")
        lines.extend(
            [
                "",
                "---",
                "승인하기 전에 원본 프로그램 페이지와 이 문서를 대조해 검토하세요.",
                "",
            ]
        )
        return "\n".join(lines)

    @classmethod
    def _render_asset_table(cls, assets) -> list[str]:
        if not assets:
            return ["명시적으로 식별된 자산이 없습니다."]
        lines = [
            "| Type | Asset | Eligibility | Maximum severity | Description |",
            "|---|---|---|---|---|",
        ]
        for asset in assets:
            lines.append(
                "| "
                + " | ".join(
                    [
                        cls._clean(asset.asset_type.value),
                        cls._clean(asset.asset),
                        cls._clean(asset.eligibility),
                        cls._clean(asset.maximum_severity),
                        cls._clean(asset.description),
                    ]
                )
                + " |"
            )
        return lines

    @classmethod
    def _render_list_section(cls, title: str, values: list[str]) -> list[str]:
        lines = ["", f"## {title}", ""]
        if values:
            lines.extend(f"- {cls._clean(value)}" for value in values)
        else:
            lines.append("- 명시된 내용 없음.")
        return lines
