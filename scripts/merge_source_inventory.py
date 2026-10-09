#!/usr/bin/env python3
"""Snapshot and verify selected files from the nested AI-DAST-ALL tree."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path


class SourceDriftError(RuntimeError):
    """A selected source is unsafe, absent, or different from its manifest."""


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _selected_path(source_root: Path, relative: str) -> Path:
    root = source_root.expanduser().resolve(strict=True)
    candidate = root / relative
    try:
        path = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise SourceDriftError(f"selected source is missing: {relative}") from exc
    if root not in path.parents or not path.is_file():
        raise SourceDriftError(f"invalid selected source: {relative}")
    relative_parts = Path(relative).parts
    if any(
        part in {".git", ".venv", "result", "__pycache__"}
        for part in relative_parts
    ) or path.suffix in {".pyc", ".db"}:
        raise SourceDriftError(f"generated source is forbidden: {relative}")
    return path


def snapshot(source_root: Path, paths: Sequence[str]) -> dict[str, str]:
    """Return sorted SHA-256 entries for explicit, repository-local files."""
    result: dict[str, str] = {}
    for relative in sorted(set(paths)):
        result[relative] = _digest(_selected_path(source_root, relative))
    return result


def verify(source_root: Path, manifest: Mapping[str, str]) -> None:
    """Raise when any manifest entry is absent or has changed."""
    changed: list[str] = []
    for relative, expected in sorted(manifest.items()):
        try:
            actual = _digest(_selected_path(source_root, relative))
        except SourceDriftError:
            changed.append(relative)
            continue
        if actual != expected:
            changed.append(relative)
    if changed:
        raise SourceDriftError("source drift: " + ", ".join(changed))


def _load_manifest(path: Path) -> dict[str, str]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or any(
        not isinstance(name, str)
        or not isinstance(digest, str)
        or len(digest) != 64
        for name, digest in document.items()
    ):
        raise SourceDriftError("invalid source manifest")
    return document


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("snapshot")
    create.add_argument("source", type=Path)
    create.add_argument("manifest", type=Path)
    create.add_argument("paths", nargs="+")
    check = commands.add_parser("verify")
    check.add_argument("source", type=Path)
    check.add_argument("manifest", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "snapshot":
        document = snapshot(args.source, args.paths)
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    else:
        verify(args.source, _load_manifest(args.manifest))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
