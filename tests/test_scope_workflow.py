from __future__ import annotations

import json
import io
import errno
import hashlib
import os
import signal
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import ANY, MagicMock, patch

from pydantic import ValidationError
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

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
    ScopeNavigationDecision,
    SourceEvidence,
)
from aidast.scope.paths import ScopePathError, identify_program
from aidast.scope.reader import (
    PlaywrightProgramPageReader,
    ProgramPageError,
    RuntimeBrowserProgramPageReader,
    _same_program_url,
)
from aidast.web.programs import ProgramRegistrationRequest, ProgramRegistry
from aidast.web.scope_process import ScopeProcessController
from aidast.web.scope_workflow import ScopeCollectionRequest, ScopeWorkflowManager


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
    def test_collection_progress_reports_completed_steps_only_after_work(self) -> None:
        events: list[tuple[str, dict[str, int]]] = []

        class Reader:
            def read(self, _url: str) -> ProgramPage:
                self_test.assertEqual(events[-1][0], "page_read_started")
                return sample_page()

        class Agent(FakeMainAgent):
            def interpret_captured_scope(self, page: ProgramPage) -> ScopeAnalysis:
                self_test.assertEqual(events[-1][0], "analysis_started")
                return sample_analysis()

        self_test = self
        with tempfile.TemporaryDirectory() as temporary_dir:
            _, draft = ScopeCoordinator(Path(temporary_dir) / "Scope").collect_draft(
                "https://bugcrowd.com/example",
                main_agent=Agent(), primary_reader=Reader(),
                draft_root=Path(temporary_dir) / "drafts",
                progress=lambda phase, counts: events.append((phase, counts)),
            )
            self.assertTrue((draft / "Scope.md").is_file())
        self.assertEqual([phase for phase, _ in events], [
            "page_read_started", "page_read_completed", "analysis_started",
            "analysis_completed", "verification_started", "verification_completed",
            "draft_started", "draft_completed",
        ])
        self.assertEqual(events[3][1], {"in_scope": 1, "out_of_scope": 0})

    def test_authenticated_reader_is_primary_and_interpreted_offline(self) -> None:
        class UnexpectedNativeAgent(FakeMainAgent):
            interpreted = False

            def collect_scope(self, program_url: str):
                raise AssertionError("native browser must not run")

            def interpret_captured_scope(self, page: ProgramPage) -> ScopeAnalysis:
                self.interpreted = True
                return sample_analysis()

        class AuthenticatedReader:
            def read(self, url: str) -> ProgramPage:
                return sample_page()

        with tempfile.TemporaryDirectory() as temporary_dir:
            agent = UnexpectedNativeAgent()
            document = ScopeCoordinator(Path(temporary_dir) / "Scope").collect(
                "https://bugcrowd.com/example",
                main_agent=agent,
                primary_reader=AuthenticatedReader(),
                approved_by="reviewer",
                review=lambda _: True,
            )

        self.assertIsNotNone(document)
        self.assertTrue(agent.interpreted)

    def test_primary_reader_must_be_complete_before_interpretation(self) -> None:
        class UnexpectedInterpretAgent(FakeMainAgent):
            def interpret_captured_scope(self, page: ProgramPage) -> ScopeAnalysis:
                raise AssertionError("incomplete capture must not be interpreted")

        class BlockedReader:
            def read(self, url: str) -> ProgramPage:
                return sample_page().model_copy(
                    update={
                        "capture_status": CaptureStatus.BLOCKED,
                        "capture_reason": CaptureReason.AUTHENTICATION_REQUIRED,
                    }
                )

        with tempfile.TemporaryDirectory() as temporary_dir:
            with self.assertRaisesRegex(
                CoordinatorError, "AUTHENTICATION_REQUIRED"
            ):
                ScopeCoordinator(Path(temporary_dir) / "Scope").collect(
                    "https://bugcrowd.com/example",
                    main_agent=UnexpectedInterpretAgent(),
                    primary_reader=BlockedReader(),
                    approved_by="reviewer",
                    review=lambda _: True,
                )

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
    def test_captured_scope_retries_one_ungrounded_asset_with_exact_evidence(self) -> None:
        agent = CodexMainAgent()
        wrong = sample_analysis().model_copy(update={
            "in_scope_assets": [
                sample_analysis().in_scope_assets[0].model_copy(
                    update={"asset": "Public-facing applications"}
                )
            ]
        })
        agent._run_structured = MagicMock(side_effect=[wrong, sample_analysis()])

        analysis = agent.interpret_captured_scope(sample_page())

        self.assertEqual(analysis.in_scope_assets[0].asset, "*.example.com")
        self.assertEqual(agent._run_structured.call_count, 2)
        self.assertIn(
            "copied verbatim",
            agent._run_structured.call_args.kwargs["prompt"],
        )

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


class RuntimeBrowserProgramPageReaderTests(unittest.TestCase):
    def test_platform_neutral_capture_accepts_scopes_and_asset_table(self) -> None:
        text = (
            "Cryptobox program rules. Scopes Scope Type Asset value "
            "https://bounty.example.com Web application. "
            "Out of scopes: other systems are excluded. "
        ) * 8
        self.assertEqual(
            PlaywrightProgramPageReader._classify_capture(
                text,
                final_url="https://yeswehack.com/programs/example",
                has_scope_view=False,
            ),
            (CaptureStatus.COMPLETE, CaptureReason.NONE),
        )

    def test_navigation_decision_uses_offline_codex_output(self) -> None:
        agent = CodexMainAgent()
        expected = ScopeNavigationDecision(action="open", candidate_id=0)
        agent._run_structured = MagicMock(return_value=expected)

        result = agent.choose_scope_view(
            program_url="https://yeswehack.com/programs/example",
            page_text="Program rules and a link to the asset list",
            candidates=[{"id": 0, "label": "Assets"}],
        )

        self.assertEqual(result, expected)
        self.assertFalse(agent._run_structured.call_args.kwargs["allow_browser"])
        self.assertIn("Assets", agent._run_structured.call_args.kwargs["prompt"])

    def test_agent_opens_observed_control_then_captures_program_page(self) -> None:
        url = "https://yeswehack.com/programs/example"
        page = MagicMock(url=url)
        page.title.return_value = "Example program"
        page.wait_for_timeout.return_value = None
        control = MagicMock()
        decisions = iter([
            ScopeNavigationDecision(action="open", candidate_id=0),
            ScopeNavigationDecision(action="capture", candidate_id=None),
        ])
        reader = RuntimeBrowserProgramPageReader(
            identity="researcher",
            timeout_seconds=1,
            navigation_agent=lambda _text, _choices: next(decisions),
        )
        body = ("Rules and Scopes. https://bounty.example.com is listed. " * 20)
        reader._wait_for_stable_text = MagicMock(return_value=body)
        reader._navigation_candidates = MagicMock(return_value=(
            [{"id": 0, "label": "Assets"}], {0: control}
        ))

        captured = reader._capture_agent_guided(page, url)

        self.assertEqual(captured.capture_status, CaptureStatus.COMPLETE)
        self.assertIn("https://bounty.example.com", captured.text)
        control.click.assert_called_once_with(timeout=5_000)

    def test_navigation_combines_tabs_and_avoids_reopening_a_control_on_revisit(self) -> None:
        url = "https://hackerone.com/example?type=team"
        page = MagicMock(url=url)
        page.title.return_value = "Example program"
        page.wait_for_timeout.return_value = None
        other = MagicMock()
        scope = MagicMock()
        clicks = 0

        def open_other(*, timeout):
            nonlocal clicks
            self.assertEqual(timeout, 5_000)
            clicks += 1
            page.url = url + ("&tab=other" if clicks == 1 else "")

        other.click.side_effect = open_other
        scope.click.side_effect = lambda *, timeout: setattr(page, "url", url + "&tab=scope")
        overview = "Program policy and testing rules. " * 30
        other_text = "General program information. " * 30
        scope_text = "In-scope assets: https://app.example.com. " * 30
        decisions = iter([
            ScopeNavigationDecision(action="open", candidate_id=0),
            ScopeNavigationDecision(action="open", candidate_id=0),
            ScopeNavigationDecision(action="open", candidate_id=1),
            ScopeNavigationDecision(action="capture", candidate_id=None),
        ])
        observed = []

        def choose(text, choices):
            observed.append((text, [choice["id"] for choice in choices]))
            return next(decisions)

        reader = RuntimeBrowserProgramPageReader(identity="researcher", navigation_agent=choose)
        reader._wait_for_stable_text = lambda current: (
            scope_text if "tab=scope" in current.url else
            other_text if "tab=other" in current.url else overview
        )
        reader._navigation_candidates = lambda *_args: (
            [{"id": 0, "label": "Overview"}, {"id": 1, "label": "Scope"}],
            {0: other, 1: scope},
        )

        captured = reader._capture_agent_guided(page, url)

        self.assertEqual(captured.capture_status, CaptureStatus.COMPLETE)
        self.assertIn("Program policy and testing rules.", captured.text)
        self.assertIn("In-scope assets: https://app.example.com.", captured.text)
        self.assertEqual(observed[2][1], [1])
        self.assertIn(overview, observed[3][0])
        self.assertIn(scope_text, observed[3][0])
        self.assertEqual(other.click.call_count, 2)
        scope.click.assert_called_once()

    def test_agent_cannot_open_external_target_link(self) -> None:
        url = "https://yeswehack.com/programs/example"
        internal = MagicMock()
        internal.is_visible.return_value = True
        internal.inner_text.return_value = "Assets"
        internal.get_attribute.side_effect = lambda name: (
            "/programs/example?tab=assets" if name == "href" else None
        )
        external = MagicMock()
        external.is_visible.return_value = True
        external.inner_text.return_value = "Test target"
        external.get_attribute.side_effect = lambda name: (
            "https://bounty.example.com" if name == "href" else None
        )
        controls = MagicMock()
        controls.evaluate_all.return_value = [
            {"index": 0, "visible": True, "type": "", "label": "Assets", "href": "/programs/example?tab=assets"},
            {"index": 1, "visible": True, "type": "", "label": "Test target", "href": "https://bounty.example.com"},
        ]
        controls.nth.side_effect = [internal, external]
        page = MagicMock(url=url)
        page.locator.return_value = controls
        reader = RuntimeBrowserProgramPageReader(identity="researcher")

        choices, locators = reader._navigation_candidates(page, url)

        self.assertEqual(choices, [{"id": 0, "label": "Assets"}])
        self.assertEqual(list(locators), [0])
        controls.evaluate_all.assert_called_once()
        controls.count.assert_not_called()

    def test_icon_control_uses_accessible_label(self) -> None:
        url = "https://yeswehack.com/programs/example"
        control = MagicMock()
        control.is_visible.return_value = True
        control.inner_text.return_value = ""
        control.get_attribute.side_effect = lambda name: (
            "View assets" if name == "aria-label" else None
        )
        controls = MagicMock()
        controls.evaluate_all.return_value = [
            {"index": 0, "visible": True, "type": "", "label": "View assets", "href": ""},
        ]
        controls.nth.return_value = control
        page = MagicMock(url=url)
        page.locator.return_value = controls

        choices, locators = RuntimeBrowserProgramPageReader(
            identity="researcher"
        )._navigation_candidates(page, url)

        self.assertEqual(choices, [{"id": 0, "label": "View assets"}])
        self.assertEqual(list(locators), [0])

    def test_navigation_request_outside_program_is_blocked(self) -> None:
        route = MagicMock()
        route.request.is_navigation_request.return_value = True
        route.request.url = "https://bounty.example.com/"

        RuntimeBrowserProgramPageReader._guard_program_navigation(
            route, "https://yeswehack.com/programs/example"
        )

        route.abort.assert_called_once_with("blockedbyclient")
        route.continue_.assert_not_called()

    def test_stable_text_retries_transient_body_timeout(self) -> None:
        text = "in scope " * 100
        page = MagicMock()
        page.locator.return_value.inner_text.side_effect = [
            PlaywrightTimeoutError("SPA still loading"),
            text,
            text,
            text,
            text,
        ]
        reader = RuntimeBrowserProgramPageReader(
            identity="researcher",
            timeout_seconds=1,
            session_root=Path("unused-in-this-test"),
        )

        self.assertEqual(reader._wait_for_stable_text(page), text.strip())

    def test_program_url_match_requires_exact_origin_and_path(self) -> None:
        expected = "https://app.intigriti.com/researcher/programs/a/b/detail"
        self.assertTrue(_same_program_url(expected, expected + "?tab=scope"))
        self.assertTrue(_same_program_url(expected + "/", expected))
        self.assertTrue(
            _same_program_url(
                expected,
                "https://app.intigriti.com/programs/a/b/detail",
            )
        )
        self.assertTrue(
            _same_program_url(
                expected,
                "https://app.intigriti.com/programs/a/b/detail/scope",
            )
        )
        self.assertFalse(
            _same_program_url(
                expected,
                "http://app.intigriti.com/researcher/programs/a/b/detail",
            )
        )
        self.assertFalse(
            _same_program_url(expected, "https://app.intigriti.com/login")
        )
        self.assertFalse(
            _same_program_url(
                expected,
                "https://example.com/researcher/programs/a/b/detail",
            )
        )
        self.assertFalse(
            _same_program_url(
                expected,
                "https://app.intigriti.com/programs/a/another/detail",
            )
        )

    def test_runtime_browser_uses_persistent_profile_and_captures_exact_page(self) -> None:
        url = "https://app.intigriti.com/researcher/programs/a/b/detail"
        text = ("Program rules and in scope assets. example.com is in scope. " * 20)
        page = MagicMock()
        page.url = url
        page.title.return_value = "Program"
        page.goto.return_value = MagicMock(status=200, url=url)
        page.locator.return_value.inner_text.return_value = text
        page.locator.return_value.count.return_value = 0
        page.get_by_text.return_value.count.return_value = 0

        context = MagicMock()
        context.pages = [page]
        playwright = MagicMock()
        playwright.chromium.launch_persistent_context.return_value = context
        manager = MagicMock()
        manager.__enter__.return_value = playwright
        prompt = MagicMock(return_value="")
        messages: list[str] = []

        with tempfile.TemporaryDirectory() as temporary_dir, patch(
            "aidast.scope.reader._validate_public_https_url"
        ), patch("aidast.scope.reader.sync_playwright", return_value=manager):
            reader = RuntimeBrowserProgramPageReader(
                identity="intigriti-user",
                timeout_seconds=1,
                session_root=Path(temporary_dir),
                input_fn=prompt,
                output_fn=messages.append,
            )
            captured = reader.read(url)

            kwargs = playwright.chromium.launch_persistent_context.call_args.kwargs
            self.assertFalse(kwargs["headless"])
            self.assertIn("browser-profile", kwargs["user_data_dir"])
            self.assertEqual(captured.capture_status, CaptureStatus.COMPLETE)
            self.assertEqual(captured.final_url.unicode_string(), url)
            context.route.assert_not_called()
            page.get_by_text.assert_not_called()
            prompt.assert_not_called()
            self.assertTrue(any("로그인 없이 프로그램 정책 페이지" in message for message in messages))
            context.close.assert_called_once_with()

    def test_runtime_browser_requests_confirmation_only_after_auth_redirect(self) -> None:
        url = "https://app.intigriti.com/researcher/programs/a/b/detail"
        page = MagicMock(url="about:blank")
        page.title.return_value = "Program"
        page.locator.return_value.inner_text.return_value = "in scope *.example.com. " * 40

        def navigate(*_args, **_kwargs):
            page.url = (
                "https://app.intigriti.com/login"
                if page.goto.call_count == 1 else url
            )
            return MagicMock(status=200)

        page.goto.side_effect = navigate
        context = MagicMock(pages=[page])
        playwright = MagicMock()
        playwright.chromium.launch_persistent_context.return_value = context
        manager = MagicMock()
        manager.__enter__.return_value = playwright
        prompt = MagicMock(return_value="")
        messages: list[str] = []

        with tempfile.TemporaryDirectory() as temporary_dir, patch(
            "aidast.scope.reader._validate_public_https_url"
        ), patch("aidast.scope.reader.sync_playwright", return_value=manager):
            reader = RuntimeBrowserProgramPageReader(
                identity="researcher", timeout_seconds=1,
                session_root=Path(temporary_dir),
                input_fn=prompt, output_fn=messages.append,
            )
            captured = reader.read(url)

        self.assertEqual(captured.capture_status, CaptureStatus.COMPLETE)
        prompt.assert_called_once()
        self.assertEqual(page.goto.call_count, 2)
        self.assertTrue(any("로그인 또는 접근 확인이 필요" in message for message in messages))

    def test_runtime_browser_rejects_page_that_did_not_return_to_program(self) -> None:
        with self.assertRaisesRegex(
            ProgramPageError, "observed same-origin paths: /login"
        ):
            RuntimeBrowserProgramPageReader._select_program_page(
                [MagicMock(url="https://app.intigriti.com/login")],
                "https://app.intigriti.com/researcher/programs/a/b/detail",
            )

    def test_runtime_browser_returns_from_program_picker_to_registered_url(self) -> None:
        url = "https://app.intigriti.com/researcher/programs/a/b/detail"
        page = MagicMock(url="https://app.intigriti.com/researcher/programs")
        page.goto.side_effect = lambda *_args, **_kwargs: setattr(page, "url", url)
        messages: list[str] = []
        reader = RuntimeBrowserProgramPageReader(
            identity="researcher", output_fn=messages.append
        )

        selected = reader._return_to_program_page([page], page, url)

        self.assertIs(selected, page)
        page.goto.assert_called_once_with(
            url, wait_until="domcontentloaded", timeout=45_000
        )
        page.bring_to_front.assert_called_once_with()
        self.assertTrue(any("등록된 프로그램 URL" in message for message in messages))
        self.assertTrue(any("페이지 이동을 확인" in message for message in messages))
        self.assertLess(
            next(i for i, message in enumerate(messages) if "페이지 응답을 받았습니다" in message),
            next(i for i, message in enumerate(messages) if "페이지 이동을 확인" in message),
        )

    def test_runtime_browser_does_not_reuse_hidden_program_tab(self) -> None:
        url = "https://app.intigriti.com/researcher/programs/a/b/detail"
        hidden_program_tab = MagicMock(url=url)
        visible_picker = MagicMock(
            url="https://app.intigriti.com/researcher/programs"
        )
        visible_picker.goto.side_effect = lambda *_args, **_kwargs: setattr(
            visible_picker, "url", url
        )
        reader = RuntimeBrowserProgramPageReader(
            identity="researcher", output_fn=lambda _message: None
        )

        selected = reader._return_to_program_page(
            [hidden_program_tab, visible_picker], hidden_program_tab, url
        )

        self.assertIs(selected, visible_picker)
        hidden_program_tab.goto.assert_not_called()
        visible_picker.goto.assert_called_once_with(
            url, wait_until="domcontentloaded", timeout=45_000
        )
        visible_picker.bring_to_front.assert_called_once_with()

    def test_runtime_browser_reports_picker_redirect_after_return(self) -> None:
        url = "https://app.intigriti.com/researcher/programs/a/b/detail"
        page = MagicMock(url="https://app.intigriti.com/researcher/programs")
        page.goto.return_value = MagicMock(status=200)
        reader = RuntimeBrowserProgramPageReader(
            identity="researcher", output_fn=lambda _message: None
        )

        with self.assertRaisesRegex(ProgramPageError, "observed same-origin paths"):
            reader._return_to_program_page([page], page, url)

        page.goto.assert_called_once_with(
            url, wait_until="domcontentloaded", timeout=45_000
        )

    def test_scope_parser_exposes_authenticated_browser_options(self) -> None:
        from aidast.cli import _parser

        args = _parser().parse_args(
            [
                "scope",
                "https://app.intigriti.com/researcher/programs/a/b/detail",
                "--login-mode",
                "runtime-browser",
                "--identity",
                "researcher",
            ]
        )
        self.assertEqual(args.scope_login_mode, "runtime-browser")
        self.assertEqual(args.scope_identity, "researcher")

@unittest.skipUnless(os.name in {"posix", "nt"}, "Scope process controls require POSIX or Windows")
class ScopeProcessControlTests(unittest.TestCase):
    def test_browser_confirmation_reaches_isolated_worker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            (root / "fake_scope_worker.py").write_text(
                "import sys\n"
                "from pathlib import Path\n"
                "from aidast.web.programs import ProgramRegistry\n"
                "from aidast.web.scope_workflow import ScopeWorkflowManager\n"
                "root, program_id, job_id = sys.argv[1:]\n"
                "sys.stdin.read()\n"
                "manager = ScopeWorkflowManager(Path(root), ProgramRegistry(Path(root)), worker_mode=True)\n"
                "manager._update(job_id, status='awaiting_browser', level='warning', message='ready', message_code='scope.browser_ready')\n"
                "manager._wait_for_browser_confirmation(job_id)\n"
                "manager._update(job_id, status='review_required', level='success', message='done', message_code='scope.review_required')\n",
                encoding="utf-8",
            )
            registry = ProgramRegistry(root)
            program_id = registry.register(ProgramRegistrationRequest(
                program_url="https://example.com/programs/test",
                visibility="public",
            ))["id"]
            controller = ScopeProcessController(
                root, project_root=root, worker_module="fake_scope_worker"
            )
            manager = ScopeWorkflowManager(
                root, registry, process_controller=controller
            )
            job_id = manager.start(program_id, ScopeCollectionRequest())["scope_job_id"]
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline and manager.get_job(program_id)["scope_status"] == "collecting":
                    time.sleep(0.05)
                self.assertEqual(manager.get_job(program_id)["scope_status"], "awaiting_browser")
                self.assertEqual(manager.browser_ready(program_id)["scope_status"], "collecting")
                while time.monotonic() < deadline and manager.get_job(program_id)["scope_status"] == "collecting":
                    time.sleep(0.05)
                self.assertEqual(manager.get_job(program_id)["scope_status"], "review_required")
            finally:
                if controller.pid(job_id) is not None:
                    controller.kill(job_id)
                cleanup_deadline = time.monotonic() + 5
                while controller._marker(job_id).exists() and time.monotonic() < cleanup_deadline:
                    time.sleep(0.05)

    def test_live_worker_pauses_continues_and_cancels_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            (root / "fake_scope_worker.py").write_text(
                "import sys, time\nsys.stdin.read()\nwhile True: time.sleep(0.1)\n",
                encoding="utf-8",
            )
            registry = ProgramRegistry(root)
            program_id = registry.register(ProgramRegistrationRequest(
                program_url="https://example.com/programs/test",
                visibility="public",
            ))["id"]
            controller = ScopeProcessController(
                root, project_root=root, worker_module="fake_scope_worker"
            )
            manager = ScopeWorkflowManager(
                root, registry, process_controller=controller
            )
            job = manager.start(program_id, ScopeCollectionRequest())
            job_id = job["scope_job_id"]
            try:
                self.assertIsNotNone(controller.pid(job_id))
                self.assertEqual(manager.pause(program_id)["scope_status"], "paused")
                self.assertEqual(manager.continue_job(program_id)["scope_status"], "collecting")
                self.assertEqual(manager.pause(program_id)["scope_status"], "paused")
                self.assertIn(manager.cancel(program_id)["scope_status"], {"cancelling", "cancelled"})
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and manager.get_job(program_id)["scope_status"] != "cancelled":
                    time.sleep(0.05)
                self.assertEqual(manager.get_job(program_id)["scope_status"], "cancelled")
                self.assertIsNone(controller.pid(job_id))
            finally:
                if controller.pid(job_id) is not None:
                    controller.kill(job_id)
                cleanup_deadline = time.monotonic() + 5
                while controller._marker(job_id).exists() and time.monotonic() < cleanup_deadline:
                    time.sleep(0.05)


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
    def test_scope_runtime_browser_uses_authenticated_primary_reader(self) -> None:
        class AuthenticatedReader:
            def read(self, url: str) -> ProgramPage:
                return sample_page()

        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir) / "Scope"
            with (
                patch("aidast.cli.CodexMainAgent", return_value=FakeMainAgent()),
                patch(
                    "aidast.cli.RuntimeBrowserProgramPageReader",
                    return_value=AuthenticatedReader(),
                ) as reader_type,
                patch("builtins.input", return_value="y"),
                redirect_stdout(io.StringIO()),
            ):
                result = main(
                    [
                        "scope",
                        "https://bugcrowd.com/engagements/example",
                        "--output-dir",
                        str(root),
                        "--login-mode",
                        "runtime-browser",
                        "--identity",
                        "researcher",
                    ]
                )

        self.assertEqual(result, 0)
        reader_type.assert_called_once_with(
            identity="researcher", timeout_seconds=45.0,
            navigation_agent=ANY,
        )

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

    def test_aidast_scope_approval_saves_configured_scope_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir) / "result" / "Scope"
            with (
                patch("aidast.cli.CodexMainAgent", return_value=FakeMainAgent()),
                patch("builtins.input", return_value="y"),
                redirect_stdout(io.StringIO()),
            ):
                result = main([
                    "scope", "https://bugcrowd.com/engagements/example",
                    "--output-dir", str(root),
                ])

            output = root / "bugcrowd" / "example"
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
