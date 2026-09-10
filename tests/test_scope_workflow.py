from __future__ import annotations

import json
import io
import errno
import hashlib
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from pydantic import ValidationError

from aidast.agents.main import CodexMainAgent, MainAgentError
from aidast.cli import main
from aidast.orchestration.scope import CoordinatorError, ScopeCoordinator
from aidast.scope.models import (
    AssetType,
    CaptureReason,
    CaptureStatus,
    ProgramPage,
    ScopeAnalysis,
    ScopeAsset,
    ScopeCollectionResult,
    SourceEvidence,
)
from aidast.scope.paths import ScopePathError, identify_program


def sample_page() -> ProgramPage:
    text = (
        "Example public bug bounty policy with explicit scope. "
        "*.example.com is in scope. "
    ) * 20
    return ProgramPage(
        requested_url="https://bugcrowd.com/example",
        final_url="https://bugcrowd.com/example",
        title="Example Program",
        captured_at=datetime(2026, 8, 24, tzinfo=timezone.utc),
        capture_status=CaptureStatus.COMPLETE,
        capture_reason=CaptureReason.NONE,
        content_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        text=text,
    )


def sample_analysis() -> ScopeAnalysis:
    return ScopeAnalysis(
        program_name="Example <Program>",
        program_description="Public bug bounty program.",
        in_scope_assets=[
            ScopeAsset(
                asset_type=AssetType.WILDCARD,
                asset="*.example.com",
                description="Public web applications",
                eligibility="Bounty eligible",
                maximum_severity="Critical",
            )
        ],
        out_of_scope_assets=[],
        allowed_activities=["Non-destructive security testing"],
        prohibited_activities=["Denial of service"],
        submission_requirements=["Provide reproducible steps"],
        operational_constraints=["Use no more than two requests per second"],
        safe_harbor="Research complying with the policy is authorized.",
        ambiguities=[],
        source_evidence=[
            SourceEvidence(section="Scope", quote="*.example.com is in scope")
        ],
    )


class FakeMainAgent:
    def collect_scope(self, program_url: str) -> tuple[ProgramPage, ScopeAnalysis]:
        return sample_page(), sample_analysis()

    def interpret_captured_scope(self, page: ProgramPage) -> ScopeAnalysis:
        return sample_analysis()


class ScopeCoordinatorTests(unittest.TestCase):
    def test_normalizes_relative_publish_destination_to_absolute_path(self) -> None:
        coordinator = ScopeCoordinator("Scope/example")

        self.assertTrue(coordinator.output_dir.is_absolute())
        self.assertEqual(
            coordinator.output_dir,
            (Path.cwd() / "Scope" / "example").resolve(),
        )

    def test_cross_device_publish_falls_back_to_sibling_copy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            output = Path(temporary_dir) / "Scope"
            real_replace = os.replace
            calls = 0

            def replace_with_one_exdev(source, destination):
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise OSError(errno.EXDEV, "Invalid cross-device link")
                return real_replace(source, destination)

            with patch(
                "aidast.orchestration.scope.os.replace",
                side_effect=replace_with_one_exdev,
            ):
                document = ScopeCoordinator(output).collect(
                    "https://bugcrowd.com/example",
                    main_agent=FakeMainAgent(),
                    approved_by="reviewer",
                    review=lambda _: True,
                )

            self.assertIsNotNone(document)
            self.assertEqual(calls, 2)
            self.assertTrue((output / "Scope.md").is_file())
            self.assertTrue((output / "Approval.json").is_file())

    def test_collect_publishes_only_an_approved_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            output = Path(temporary_dir) / "Scope"
            reviewed_paths: list[Path] = []

            def approve(scope_path: Path) -> bool:
                self.assertTrue(scope_path.is_file())
                reviewed_paths.append(scope_path)
                return True

            document = ScopeCoordinator(output).collect(
                "https://bugcrowd.com/example",
                main_agent=FakeMainAgent(),
                approved_by="reviewer",
                review=approve,
            )

            self.assertIsNotNone(document)
            assert document is not None
            self.assertEqual(document.analysis.program_name, "Example <Program>")
            self.assertEqual(len(reviewed_paths), 1)
            self.assertFalse(reviewed_paths[0].exists())
            self.assertTrue((output / "Scope.md").is_file())
            self.assertTrue((output / "Scope.json").is_file())
            self.assertTrue((output / "Manifest.json").is_file())
            self.assertTrue((output / "Approval.json").is_file())
            markdown = (output / "Scope.md").read_text(encoding="utf-8")
            self.assertIn("# Scope: Example &lt;Program&gt;", markdown)
            self.assertIn("*.example.com", markdown)

    def test_rejected_scope_is_discarded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            output = Path(temporary_dir) / "Scope"
            reviewed_paths: list[Path] = []

            def reject(scope_path: Path) -> bool:
                self.assertTrue(scope_path.is_file())
                reviewed_paths.append(scope_path)
                return False

            document = ScopeCoordinator(output).collect(
                "https://bugcrowd.com/example",
                main_agent=FakeMainAgent(),
                approved_by="reviewer",
                review=reject,
            )

            self.assertIsNone(document)
            self.assertFalse(output.exists())
            self.assertEqual(len(reviewed_paths), 1)
            self.assertFalse(reviewed_paths[0].exists())

    def test_approval_detects_subsequent_scope_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            output = Path(temporary_dir) / "Scope"
            coordinator = ScopeCoordinator(output)
            coordinator.collect(
                "https://bugcrowd.com/example",
                main_agent=FakeMainAgent(),
                approved_by="reviewer",
                review=lambda _: True,
            )
            approval = coordinator.verify_approval()
            self.assertEqual(approval.approved_by, "reviewer")

            with (output / "Scope.md").open("a", encoding="utf-8") as handle:
                handle.write("modified\n")
            with self.assertRaisesRegex(CoordinatorError, "changed"):
                coordinator.verify_approval()

    def test_collect_refuses_to_overwrite_existing_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            output = Path(temporary_dir) / "Scope"
            output.mkdir()
            (output / "user-file.txt").write_text("keep", encoding="utf-8")
            with self.assertRaisesRegex(CoordinatorError, "already exists"):
                ScopeCoordinator(output).collect(
                    "https://bugcrowd.com/example",
                    main_agent=FakeMainAgent(),
                    approved_by="reviewer",
                    review=lambda _: True,
                )
            self.assertEqual(
                (output / "user-file.txt").read_text(encoding="utf-8"), "keep"
            )

    def test_partial_capture_cannot_be_approved(self) -> None:
        class PartialMainAgent:
            def collect_scope(
                self, program_url: str
            ) -> tuple[ProgramPage, ScopeAnalysis]:
                return (
                    sample_page().model_copy(
                        update={
                            "capture_status": CaptureStatus.PARTIAL,
                            "capture_reason": CaptureReason.CONTENT_INCOMPLETE,
                        }
                    ),
                    sample_analysis(),
                )

        with tempfile.TemporaryDirectory() as temporary_dir:
            output = Path(temporary_dir) / "Scope"
            coordinator = ScopeCoordinator(output)
            with self.assertRaisesRegex(CoordinatorError, "incomplete"):
                coordinator.collect(
                    "https://bugcrowd.com/example",
                    main_agent=PartialMainAgent(),
                    approved_by="reviewer",
                    review=lambda _: True,
                )
            self.assertFalse(output.exists())

    def test_uses_deterministic_browser_when_native_capture_is_blocked(self) -> None:
        class BlockedMainAgent(FakeMainAgent):
            fallback_interpreted = False

            def collect_scope(
                self, program_url: str
            ) -> tuple[ProgramPage, ScopeAnalysis]:
                return (
                    sample_page().model_copy(
                        update={
                            "capture_status": CaptureStatus.BLOCKED,
                            "capture_reason": (
                                CaptureReason.JAVASCRIPT_RENDER_INCOMPLETE
                            ),
                        }
                    ),
                    sample_analysis(),
                )

            def interpret_captured_scope(self, page: ProgramPage) -> ScopeAnalysis:
                self.fallback_interpreted = True
                return sample_analysis()

        class CompleteFallbackReader:
            def read(self, url: str) -> ProgramPage:
                return sample_page()

        with tempfile.TemporaryDirectory() as temporary_dir:
            output = Path(temporary_dir) / "Scope"
            main_agent = BlockedMainAgent()
            document = ScopeCoordinator(output).collect(
                "https://bugcrowd.com/example",
                main_agent=main_agent,
                fallback_reader=CompleteFallbackReader(),
                approved_by="reviewer",
                review=lambda _: True,
            )

            self.assertIsNotNone(document)
            self.assertTrue(main_agent.fallback_interpreted)
            self.assertTrue((output / "Scope.md").is_file())

    def test_does_not_fallback_for_authentication_required(self) -> None:
        class AuthRequiredMainAgent(FakeMainAgent):
            def collect_scope(
                self, program_url: str
            ) -> tuple[ProgramPage, ScopeAnalysis]:
                return (
                    sample_page().model_copy(
                        update={
                            "capture_status": CaptureStatus.BLOCKED,
                            "capture_reason": CaptureReason.AUTHENTICATION_REQUIRED,
                        }
                    ),
                    sample_analysis(),
                )

        class UnexpectedFallbackReader:
            def read(self, url: str) -> ProgramPage:
                raise AssertionError("fallback must not run for authentication")

        with tempfile.TemporaryDirectory() as temporary_dir:
            output = Path(temporary_dir) / "Scope"
            with self.assertRaisesRegex(CoordinatorError, "blocked"):
                ScopeCoordinator(output).collect(
                    "https://bugcrowd.com/example",
                    main_agent=AuthRequiredMainAgent(),
                    fallback_reader=UnexpectedFallbackReader(),
                    approved_by="reviewer",
                    review=lambda _: True,
                )
            self.assertFalse(output.exists())


class CodexMainAgentTests(unittest.TestCase):
    def test_scope_collection_prompt_invokes_native_skill_with_url(self) -> None:
        prompt = CodexMainAgent._build_scope_collection_prompt(
            "https://bugcrowd.com/engagements/example"
        )
        self.assertIn("$aidast-scope", prompt)
        self.assertIn("https://bugcrowd.com/engagements/example", prompt)

    def test_codex_native_skill_collects_and_interprets_scope(self) -> None:
        collection = ScopeCollectionResult(
            final_url="https://bugcrowd.com/engagements/example",
            title="Example Program",
            capture_status=CaptureStatus.COMPLETE,
            capture_reason=CaptureReason.NONE,
            captured_text=sample_page().text,
            analysis=sample_analysis(),
        )
        with tempfile.TemporaryDirectory() as temporary_dir:
            executable = Path(temporary_dir) / "codex-test"
            executable.write_text(
                "#!/usr/bin/env python3\n"
                "import json, pathlib, sys\n"
                "if sys.argv[1:3] == ['login', 'status']:\n"
                "    raise SystemExit(0)\n"
                "work = pathlib.Path(sys.argv[sys.argv.index('--cd') + 1])\n"
                "assert (work / '.agents/skills/aidast-scope/SKILL.md').is_file()\n"
                "assert '--enable' in sys.argv and 'browser_use' in sys.argv\n"
                "prompt = sys.stdin.read()\n"
                "assert '$aidast-scope' in prompt\n"
                "output = pathlib.Path(sys.argv[sys.argv.index('--output-last-message') + 1])\n"
                f"output.write_text({json.dumps(collection.model_dump(mode='json'))!r})\n",
                encoding="utf-8",
            )
            executable.chmod(executable.stat().st_mode | 0o111)

            page, analysis = CodexMainAgent(
                executable=str(executable), timeout_seconds=10
            ).collect_scope("https://bugcrowd.com/engagements/example")

            self.assertEqual(page.title, "Example Program")
            self.assertEqual(analysis.program_name, "Example <Program>")
            self.assertEqual(analysis.in_scope_assets[0].asset, "*.example.com")

    def test_rejects_ungrounded_in_scope_asset(self) -> None:
        analysis = sample_analysis().model_copy(
            update={
                "in_scope_assets": [
                    ScopeAsset(
                        asset_type=AssetType.DOMAIN,
                        asset="hallucinated.example",
                        description="Not in source",
                        eligibility="Unknown",
                        maximum_severity="Unknown",
                    )
                ]
            }
        )
        with self.assertRaisesRegex(MainAgentError, "ungrounded in-scope asset"):
            CodexMainAgent._verify_grounding(sample_page(), analysis)


class ScopeModelTests(unittest.TestCase):
    def test_rejects_whitespace_only_asset_and_evidence(self) -> None:
        with self.assertRaises(ValidationError):
            ScopeAsset(
                asset_type=AssetType.DOMAIN,
                asset=" ",
                description="",
                eligibility="",
                maximum_severity="",
            )
        with self.assertRaises(ValidationError):
            SourceEvidence(section="Scope", quote=" ")


class CliTests(unittest.TestCase):
    def test_scope_reports_extraction_before_review(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir) / "Scope"
            console = io.StringIO()
            with (
                patch("aidast.cli.CodexMainAgent", return_value=FakeMainAgent()),
                patch("builtins.input", return_value="n"),
                redirect_stdout(console),
            ):
                main([
                    "scope", "https://bugcrowd.com/engagements/example",
                    "--output-dir", str(root),
                ])
            output = console.getvalue()
            self.assertIn("Scope 추출 및 정책 해석이 완료되었습니다.", output)
            self.assertIn("In-scope 자산: 1개", output)
            self.assertIn("Temporary Scope draft:", output)

    def test_aidast_scope_approval_saves_default_scope_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            previous_directory = Path.cwd()
            os.chdir(temporary_dir)
            try:
                with (
                    patch("aidast.cli.CodexMainAgent", return_value=FakeMainAgent()),
                    patch("builtins.input", return_value="y"),
                    redirect_stdout(io.StringIO()),
                ):
                    result = main(
                        ["scope", "https://bugcrowd.com/engagements/example"]
                    )
            finally:
                os.chdir(previous_directory)

            output = Path(temporary_dir) / "Scope" / "bugcrowd" / "example"
            self.assertEqual(result, 0)
            self.assertTrue((output / "Scope.md").is_file())
            self.assertTrue((output / "Approval.json").is_file())

    def test_aidast_scope_rejection_discards_temporary_draft(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir) / "Scope"
            output = root / "bugcrowd" / "example"
            console = io.StringIO()
            with (
                patch("aidast.cli.CodexMainAgent", return_value=FakeMainAgent()),
                patch("builtins.input", return_value="n"),
                redirect_stdout(console),
            ):
                result = main(
                    [
                        "scope",
                        "https://bugcrowd.com/engagements/example",
                        "--output-dir",
                        str(root),
                    ]
                )

            self.assertEqual(result, 1)
            self.assertFalse(output.exists())
            self.assertIn("rejected and discarded", console.getvalue())

    def test_aidast_scope_records_explicit_reviewer_on_approval(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir) / "Scope"
            output = root / "bugcrowd" / "example"
            with (
                patch("aidast.cli.CodexMainAgent", return_value=FakeMainAgent()),
                patch("builtins.input", return_value="y"),
                redirect_stdout(io.StringIO()),
            ):
                result = main(
                    [
                        "scope",
                        "https://bugcrowd.com/engagements/example",
                        "--by",
                        "security-reviewer",
                        "--output-dir",
                        str(root),
                    ]
                )

            self.assertEqual(result, 0)
            approval = json.loads(
                (output / "Approval.json").read_text(encoding="utf-8")
            )
            self.assertEqual(approval["approved_by"], "security-reviewer")

    def test_aidast_scope_status_rejects_collection_only_reviewer(self) -> None:
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                main(
                    [
                        "scope",
                        "status",
                        "https://bugcrowd.com/engagements/example",
                        "--by",
                        "ignored",
                    ]
                )
        self.assertEqual(raised.exception.code, 2)


class ScopePathTests(unittest.TestCase):
    def test_identifies_supported_program_paths(self) -> None:
        cases = {
            "https://hackerone.com/alsco": ("hackerone", "alsco"),
            "https://bugcrowd.com/engagements/aiven-mbb-og": (
                "bugcrowd",
                "aiven-mbb-og",
            ),
            "https://yeswehack.com/programs/decathlon#program-description": (
                "yeswehack",
                "decathlon",
            ),
        }
        for url, expected in cases.items():
            with self.subTest(url=url):
                location = identify_program(url)
                self.assertEqual((location.platform, location.program), expected)

    def test_rejects_non_https_program_url(self) -> None:
        with self.assertRaisesRegex(ScopePathError, "absolute HTTPS URL"):
            identify_program("http://127.0.0.1:3000/")


if __name__ == "__main__":
    unittest.main()
