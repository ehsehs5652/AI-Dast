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


# Scope 수집과 승인 과정에서 발생하는 오류를 나타냄
class CoordinatorError(RuntimeError):
    pass


# Scope 페이지 수집과 해석에 필요한 에이전트 인터페이스를 정의
class ScopeCollector(Protocol):
    # 프로그램 URL에서 페이지와 Scope 분석 결과를 함께 수집
    def collect_scope(self, program_url: str) -> tuple[ProgramPage, ScopeAnalysis]: ...

    # 이미 수집한 페이지 내용을 Scope 분석 결과로 해석
    def interpret_captured_scope(self, page: ProgramPage) -> ScopeAnalysis: ...


# 프로그램 페이지를 읽는 객체의 인터페이스를 정의
class ProgramPageReader(Protocol):
    # 지정한 URL에서 프로그램 페이지를 읽음
    def read(self, url: str) -> ProgramPage: ...


# Scope 초안 생성, 승인, 저장 및 검증을 조정
class ScopeCoordinator:
    # 승인된 Scope 산출물을 저장할 경로를 설정
    def __init__(self, output_dir: Path | str = "result/Scope") -> None:
        self.output_dir = Path(output_dir).resolve(strict=False)

    # Scope 초안을 수집하고 검토 결과에 따라 승인해 게시
    def collect(
        self,
        program_url: str,
        *,
        main_agent: ScopeCollector,
        primary_reader: ProgramPageReader | None = None,
        fallback_reader: ProgramPageReader | None = None,
        approved_by: str,
        review: Callable[[Path], bool],
    ) -> ScopeDocument | None:
        approved_by = self._validate_approver(approved_by)
        document, staging = self.collect_draft(
            program_url,
            main_agent=main_agent,
            primary_reader=primary_reader,
            fallback_reader=fallback_reader,
        )
        try:
            if not review(staging / "Scope.md"):
                return None
            return self.approve_draft(staging, approved_by=approved_by)
        finally:
            shutil.rmtree(staging, ignore_errors=True)

    # 프로그램 페이지를 분석해 아직 승인되지 않은 Scope 초안을 만듬
    def collect_draft(
        self,
        program_url: str,
        *,
        main_agent: ScopeCollector,
        primary_reader: ProgramPageReader | None = None,
        fallback_reader: ProgramPageReader | None = None,
        draft_root: Path | str | None = None,
        progress: Callable[[str, dict[str, int]], None] | None = None,
    ) -> tuple[ScopeDocument, Path]:
        """Collect an unapproved draft for a later explicit review decision."""
        def report(phase: str, **counts: int) -> None:
            if progress is not None:
                progress(phase, counts)

        if self.output_dir.exists():
            raise CoordinatorError(
                f"scope output already exists: {self.output_dir}; "
                "move or remove it before collecting a new scope"
            )
        if primary_reader is not None:
            report("page_read_started")
            page = primary_reader.read(program_url)
            self._require_complete_capture(page)
            report("page_read_completed", characters=len(page.text))
            report("analysis_started")
            analysis = main_agent.interpret_captured_scope(page)
            report("analysis_completed", in_scope=len(analysis.in_scope_assets), out_of_scope=len(analysis.out_of_scope_assets))
        else:
            report("collection_started")
            page, analysis = main_agent.collect_scope(program_url)
            report("collection_completed", characters=len(page.text), in_scope=len(analysis.in_scope_assets), out_of_scope=len(analysis.out_of_scope_assets))
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
                report("page_read_completed", characters=len(page.text))
                report("analysis_started")
                analysis = main_agent.interpret_captured_scope(page)
                report("analysis_completed", in_scope=len(analysis.in_scope_assets), out_of_scope=len(analysis.out_of_scope_assets))
        self._require_complete_capture(page)
        report("verification_started")
        self._require_grounded_analysis(page, analysis)
        report("verification_completed")
        document = ScopeDocument(
            scope_id=f"scope_{uuid4().hex}",
            created_at=datetime.now(timezone.utc),
            source=page,
            analysis=analysis,
        )
        report("draft_started")
        staging = self._create_scope_draft(document, draft_root=draft_root)
        report("draft_completed")
        return document, staging

    # 초안의 무결성을 확인하고 승인된 Scope로 게시
    def approve_draft(
        self, draft_dir: Path | str, *, approved_by: str
    ) -> ScopeDocument:
        """Verify and atomically publish one previously collected draft."""
        approved_by = self._validate_approver(approved_by)
        staging = Path(draft_dir).resolve(strict=True)
        document = self._load_model(staging / "Scope.json", ScopeDocument)
        self._require_complete_capture(document.source)
        manifest = self._load_model(staging / "Manifest.json", ScopeManifest)
        if manifest.scope_id != document.scope_id:
            raise CoordinatorError("scope document and manifest IDs do not match")
        self._verify_content_hashes(
            manifest,
            {"json": staging / "Scope.json", "markdown": staging / "Scope.md"},
        )
        self._publish_scope(staging, document, approved_by)
        return document

    # 승인자 이름이 비어 있거나 너무 길지 않은지 확인
    @staticmethod
    def _validate_approver(value: str) -> str:
        approved_by = value.strip()
        if not approved_by:
            raise CoordinatorError("approved_by must not be blank")
        if len(approved_by) > 160:
            raise CoordinatorError("approved_by must be at most 160 characters")
        return approved_by

    # 프로그램 페이지가 완전히 수집됐는지 확인
    @staticmethod
    def _require_complete_capture(page: ProgramPage) -> None:
        if page.capture_status is CaptureStatus.BLOCKED:
            raise CoordinatorError(
                "program page access was blocked "
                f"({page.capture_reason.value}); no Scope.md was generated"
            )
        if page.capture_status is not CaptureStatus.COMPLETE:
            raise CoordinatorError(
                f"program page capture is incomplete "
                f"({page.capture_reason.value}); no Scope.md was generated"
            )

    @staticmethod
    def _require_grounded_analysis(page: ProgramPage, analysis: ScopeAnalysis) -> None:
        if not analysis.program_description.strip() or not analysis.in_scope_assets:
            raise CoordinatorError(
                "Scope analysis lacks an explicit program description or target list; "
                "no Scope.md was generated"
            )
        if not (
            analysis.out_of_scope_assets
            or analysis.prohibited_activities
            or analysis.operational_constraints
        ):
            raise CoordinatorError(
                "Scope analysis lacks rules, exclusions, or constraints; "
                "no Scope.md was generated"
            )
        for evidence in analysis.source_evidence:
            if evidence.quote not in page.text:
                raise CoordinatorError(
                    "Scope analysis contains a quote absent from the captured page; "
                    "no Scope.md was generated"
                )
        for asset in analysis.in_scope_assets:
            if asset.asset not in page.text or not any(
                asset.asset in evidence.quote
                for evidence in analysis.source_evidence
            ):
                raise CoordinatorError(
                    "Scope analysis lacks exact source evidence for an in-scope asset; "
                    "no Scope.md was generated"
                )

    def verify_approval(self) -> ScopeApproval:
        approval, _, _ = self._load_verified_snapshot()
        return approval

    # 검증된 Scope 문서와 Markdown을 읽어 반환
    def load_approved_scope(self) -> tuple[ScopeDocument, str]:
        _, document, markdown = self._load_verified_snapshot()
        return document, markdown

    # 저장된 Scope 파일과 승인 정보의 내용 및 해시를 함께 검증
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

    # Scope 초안 파일과 해시 명세를 임시 디렉터리에 작성
    def _create_scope_draft(
        self, document: ScopeDocument, *, draft_root: Path | str | None = None
    ) -> Path:
        parent = (
            Path(draft_root).resolve(strict=False)
            if draft_root is not None
            else self.output_dir.parent
        )
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

    # 승인 정보를 기록하고 초안 디렉터리를 최종 위치에 게시
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
        # Dashboard drafts live under result/.webui while approved artifacts are
        # published under result/Scope/<platform>/<program>.  Ensure that nested
        # destination exists before the atomic rename/cross-device fallback.
        self.output_dir.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.replace(staging, self.output_dir)
        except OSError as exc:
            if exc.errno != errno.EXDEV:
                raise
            self._publish_cross_device(staging)

    # 파일시스템이 달라 이동할 수 없을 때 복사 후 게시
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

    # Scope JSON과 Markdown이 명세에 기록된 해시와 일치하는지 확인
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

    # JSON 파일을 지정한 모델로 읽고 유효성을 검사
    @staticmethod
    def _load_model(path: Path, model_type):
        if not path.is_file():
            raise CoordinatorError(f"required file does not exist: {path}")
        try:
            return model_type.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValidationError, ValueError) as exc:
            raise CoordinatorError(f"invalid {path.name}: {exc}") from exc

    # 파일 내용의 SHA-256 해시를 계산
    @staticmethod
    def _sha256(content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()

    # Markdown에 넣을 텍스트의 공백과 특수문자를 정리
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

    # Scope 문서를 검토용 Markdown으로 변환
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

    # Scope 자산 목록을 Markdown 표로 변환
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

    # 문자열 목록을 Markdown 제목과 항목으로 변환
    @classmethod
    def _render_list_section(cls, title: str, values: list[str]) -> list[str]:
        lines = ["", f"## {title}", ""]
        if values:
            lines.extend(f"- {cls._clean(value)}" for value in values)
        else:
            lines.append("- 명시된 내용 없음.")
        return lines
