from __future__ import annotations

import tempfile
import unittest
from importlib.resources import files
from pathlib import Path

from aidast.agents.main import CodexMainAgent


class NativeSkillTests(unittest.TestCase):
    def test_eligibility_skill_is_packaged_with_policy_only_contract(self) -> None:
        content = files("aidast.skills.validation").joinpath(
            "ELIGIBILITY_SKILL.md"
        ).read_text(encoding="utf-8")

        for value in ("ELIGIBLE", "INELIGIBLE", "CONDITIONAL", "UNKNOWN"):
            self.assertIn(value, content)
        self.assertIn("no final Validation status", content)

    def test_scope_skill_uses_codex_standard_frontmatter(self) -> None:
        content = files("aidast.skills.scope").joinpath("SKILL.md").read_text(
            encoding="utf-8"
        )

        self.assertTrue(content.startswith("---\n"))
        self.assertIn("name: aidast-scope", content)
        self.assertIn("description:", content)
        self.assertIn("# Collection Rules", content)
        self.assertIn("# Interpretation Rules", content)

    def test_stages_scope_skill_in_codex_native_discovery_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            work_dir = Path(temporary_dir)
            CodexMainAgent._stage_native_skill(
                work_dir=work_dir,
                package="aidast.skills.scope",
                skill_name="aidast-scope",
            )

            staged = (
                work_dir
                / ".agents"
                / "skills"
                / "aidast-scope"
                / "SKILL.md"
            )
            self.assertTrue(staged.is_file())
            self.assertIn("name: aidast-scope", staged.read_text(encoding="utf-8"))

    def test_target_policy_skill_is_packaged_and_staged(self) -> None:
        content = files("aidast.skills.target_policy").joinpath("SKILL.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("name: aidast-target-policy", content)
        self.assertIn("# Grounded Restrictions", content)
        self.assertIn("Do not optimize, tune", content)

        with tempfile.TemporaryDirectory() as temporary_dir:
            work_dir = Path(temporary_dir)
            CodexMainAgent._stage_native_skill(
                work_dir=work_dir,
                package="aidast.skills.target_policy",
                skill_name="aidast-target-policy",
            )
            staged = (
                work_dir
                / ".agents"
                / "skills"
                / "aidast-target-policy"
                / "SKILL.md"
            )
            self.assertTrue(staged.is_file())

    def test_validation_and_reporting_skills_stage_with_report_references(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            work_dir = Path(temporary_dir)
            CodexMainAgent._stage_native_skill(
                work_dir=work_dir,
                package="aidast.skills.validation",
                skill_name="aidast-validation",
            )
            CodexMainAgent._stage_native_skill(
                work_dir=work_dir,
                package="aidast.skills.reporting",
                skill_name="aidast-reporting",
            )
            skills = work_dir / ".agents" / "skills"
            self.assertIn(
                "name: aidast-validation",
                (skills / "aidast-validation" / "SKILL.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "name: aidast-reporting",
                (skills / "aidast-reporting" / "SKILL.md").read_text(encoding="utf-8"),
            )
            self.assertEqual(
                {path.name for path in (skills / "aidast-reporting" / "references").iterdir()},
                {"hackerone.md", "bugcrowd.md", "intigriti.md"},
            )


if __name__ == "__main__":
    unittest.main()
