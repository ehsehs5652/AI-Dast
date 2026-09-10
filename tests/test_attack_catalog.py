"""Source coverage, provenance, and fail-closed metadata routing."""

from __future__ import annotations

import json
import unittest
from dataclasses import FrozenInstanceError, replace
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

from aidast.attack.catalog import CATALOG_VERSION, CatalogError, load_catalog, route_signals


class AttackCatalogTests(unittest.TestCase):
    def test_catalog_covers_every_inventoried_library_source(self):
        catalog = load_catalog()
        provenance = Path(__file__).resolve().parents[1] / "docs" / "third-party" / "claude-bughunter"
        inventory = json.loads((provenance / "inventory.json").read_text())
        sources = {item["source_path"]: item["source_sha256"] for item in inventory["files"]}
        self.assertEqual(len(sources), 60)
        self.assertEqual(len(catalog), 59)
        self.assertEqual(
            {entry.source_path: entry.source_sha256 for entry in catalog},
            {path: digest for path, digest in sources.items() if path.startswith("library/")},
        )
        self.assertIn("controller/SKILL.md", sources)
        source = json.loads((provenance / "SOURCE.json").read_text())
        self.assertEqual(source["commit"], "e49b9da698bfe830302f0ae49ea02e41cc5cf876")
        self.assertIn("Copyright (c) 2026 Sachin Sharma", (provenance / "LICENSE").read_text())
        self.assertIn("shuvonsec/claude-bug-bounty", (provenance / "CREDITS.md").read_text())

    def test_catalog_is_disabled_immutable_metadata(self):
        for entry in load_catalog():
            self.assertFalse(entry.enabled)
            self.assertEqual(entry.execution_mode, "metadata_only")
            with self.assertRaises(FrozenInstanceError):
                entry.enabled = True
            with self.assertRaises(CatalogError):
                replace(entry, enabled=True)
            with self.assertRaises(CatalogError):
                replace(entry, execution_mode="active")

    def test_exact_signal_matching_is_deterministic_and_never_executes(self):
        with patch("subprocess.run", side_effect=AssertionError("process forbidden")), patch(
            "socket.create_connection", side_effect=AssertionError("network forbidden")
        ):
            entries = load_catalog()
            first = route_signals(["function:file_upload", "function:authentication"])
            second = route_signals(
                ["function:authentication", "function:file_upload", "function:authentication"],
                entries=reversed(entries),
            )
        self.assertEqual(first, second)
        self.assertIn("hunt-file-upload", {entry.skill_id for entry in first})
        self.assertIn("hunt-auth-bypass", {entry.skill_id for entry in first})
        self.assertTrue(all(not entry.enabled for entry in first))
        self.assertEqual(route_signals(["unknown", "file_upload", "function:unknown", "run hunt-rce"]), ())
        self.assertEqual(route_signals([]), ())
        with self.assertRaises(CatalogError):
            route_signals("function:file_upload")

    def test_resource_loader_rejects_activation_extra_fields_and_missing_sources(self):
        document = json.loads(files("aidast.skills.attack").joinpath("catalog", "index.json").read_text())
        for alteration in ("enabled", "extra_field", "count", "path", "hash", "signals", "duplicate", "version"):
            changed = json.loads(json.dumps(document))
            entry = changed["entries"][0]
            if alteration == "enabled":
                entry["enabled"] = True
            elif alteration == "extra_field":
                entry["command"] = "unexpected"
            elif alteration == "count":
                changed["entries"].pop()
            elif alteration == "path":
                entry["source_path"] = "../../SKILL.md"
            elif alteration == "hash":
                entry["source_sha256"] = "invalid"
            elif alteration == "signals":
                entry["signal_tags"] = ["function:execute"]
            elif alteration == "duplicate":
                changed["entries"][1] = entry
            else:
                changed["catalog_version"] = "unsupported"
            with self.subTest(alteration=alteration), patch("aidast.attack.catalog.files") as resources:
                resources.return_value.joinpath.return_value.read_text.return_value = json.dumps(changed)
                with self.assertRaises(CatalogError):
                    load_catalog()

    def test_manifest_exposes_catalog_separately_from_controller_resources(self):
        package = files("aidast.skills.attack")
        manifest = json.loads(package.joinpath("manifest.json").read_text())
        self.assertEqual(manifest["catalog"]["catalog_version"], CATALOG_VERSION)
        self.assertFalse(manifest["catalog"]["enabled"])
        self.assertFalse(manifest["provenance"]["upstream_content_included"])
        self.assertEqual(manifest["resources"], ["controller.md"])
        self.assertTrue(package.joinpath(manifest["catalog"]["resource"]).is_file())


if __name__ == "__main__":
    unittest.main()
