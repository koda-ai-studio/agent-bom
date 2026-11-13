#!/usr/bin/env python3
"""Fold per-PR changelog fragments into a CHANGELOG.md release section.

Each pull request adds one file, ``changelog.d/<slug>.md``, instead of editing
the ``## [Unreleased]`` section that every other open PR is also editing::

    ### Fixed
    - What changed, for whom, and what they see now (#1234).

A fragment may carry several ``### <Section>`` headings. At release time::

    python scripts/assemble_changelog.py --version 1.2.3

writes ``## [1.2.3] - <today>`` under ``## [Unreleased]`` with the sections in
canonical order, keeps any entries already written under Unreleased ahead of
the fragments, advances the compare links, and deletes the assembled
fragments. ``--check`` validates fragments without writing (CI runs it on every
PR); ``--check --expect-empty`` also fails while fragments are pending (the
release preflight runs it). Standard library only.
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Order sections appear in a release entry. Matches the headings already used
# in CHANGELOG.md history; an unknown heading is a typo, not a new section.
SECTIONS: tuple[str, ...] = (
    "Highlights",
    "Upgrade notes",
    "Added",
    "Changed",
    "Deprecated",
    "Removed",
    "Fixed",
    "Security",
    "Performance",
    "Docs",
    "CI",
)
FRAGMENT_EXCLUDE = frozenset({"README.md"})
UNRELEASED_HEADING = "## [Unreleased]"
_SECTION_RE = re.compile(r"^### (?P<name>.+?)\s*$")
_RELEASE_RE = re.compile(r"^## \[", re.MULTILINE)
_UNRELEASED_LINK_RE = re.compile(r"^\[Unreleased\]: (?P<base>\S+)/compare/v(?P<previous>[^.\s][^\s]*?)\.\.\.HEAD$", re.MULTILINE)


class FragmentError(ValueError):
    """A fragment that cannot be assembled."""


Sections = dict[str, list[str]]


def parse_entries(text: str, source: str) -> Sections:
    """Return ``{section: [entry block, ...]}`` for ``### Section`` blocks in *text*."""
    sections: Sections = {}
    current: str | None = None
    block: list[str] = []

    def close() -> None:
        body = "\n".join(block).strip("\n")
        if current is None:
            return
        if not body.strip():
            raise FragmentError(f"{source}: section '### {current}' is empty")
        sections.setdefault(current, []).append(body)

    for line in text.splitlines():
        match = _SECTION_RE.match(line)
        if match:
            close()
            current, block = match.group("name"), []
            if current not in SECTIONS:
                raise FragmentError(f"{source}: unknown section '### {current}'; use one of: {', '.join(SECTIONS)}")
            continue
        if current is None:
            if line.strip():
                raise FragmentError(f"{source}: text before the first '### <Section>' heading: {line.strip()!r}")
            continue
        block.append(line)
    close()
    if not sections:
        raise FragmentError(f"{source}: empty fragment; add a '### <Section>' heading with at least one bullet")
    return sections


def fragment_paths(directory: Path) -> list[Path]:
    if not directory.is_dir():
        return []
    return sorted(path for path in directory.glob("*.md") if path.name not in FRAGMENT_EXCLUDE and not path.name.startswith("."))


def load_fragments(paths: list[Path]) -> tuple[list[Sections], list[str]]:
    parsed: list[Sections] = []
    errors: list[str] = []
    for path in paths:
        try:
            parsed.append(parse_entries(path.read_text(encoding="utf-8"), path.name))
        except FragmentError as exc:
            errors.append(str(exc))
    return parsed, errors


def _split_unreleased(changelog: str) -> tuple[str, str, str]:
    """Split into (text through the Unreleased heading, its body, the rest)."""
    start = changelog.find(UNRELEASED_HEADING)
    if start < 0:
        raise FragmentError(f"CHANGELOG has no '{UNRELEASED_HEADING}' heading")
    head_end = start + len(UNRELEASED_HEADING)
    following = _RELEASE_RE.search(changelog, head_end)
    body_end = following.start() if following else len(changelog)
    return changelog[:head_end], changelog[head_end:body_end], changelog[body_end:]


def render_section(version: str, released_on: str, groups: list[Sections]) -> str:
    merged: Sections = {}
    for group in groups:
        for name, entries in group.items():
            merged.setdefault(name, []).extend(entries)
    lines = [f"## [{version}] - {released_on}", ""]
    for name in SECTIONS:
        if name in merged:
            lines.append(f"### {name}")
            lines.extend(merged[name])
            lines.append("")
    return "\n".join(lines) + "\n"


def assemble(changelog: str, fragments: list[Sections], version: str, released_on: str) -> str:
    if re.search(rf"^## \[{re.escape(version)}\]", changelog, re.MULTILINE):
        raise FragmentError(f"CHANGELOG already has a '## [{version}]' entry")
    head, body, rest = _split_unreleased(changelog)
    groups = ([parse_entries(body, "CHANGELOG [Unreleased]")] if body.strip() else []) + fragments
    if not groups:
        raise FragmentError("nothing to assemble: no fragments and an empty Unreleased section")
    section = render_section(version, released_on, groups)
    updated = f"{head}\n\n{section}{rest}"
    link = _UNRELEASED_LINK_RE.search(updated)
    if link:
        base, previous = link.group("base"), link.group("previous")
        updated = (
            updated[: link.start()]
            + f"[Unreleased]: {base}/compare/v{version}...HEAD\n[{version}]: {base}/compare/v{previous}...v{version}"
            + updated[link.end() :]
        )
    return updated


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", help="release version to assemble, e.g. 1.2.3")
    parser.add_argument("--date", default=date.today().isoformat(), help="release date (default: today)")
    parser.add_argument("--changelog", type=Path, default=ROOT / "CHANGELOG.md")
    parser.add_argument("--fragments-dir", type=Path, default=ROOT / "changelog.d")
    parser.add_argument("--check", action="store_true", help="validate fragments only; write nothing")
    parser.add_argument("--expect-empty", action="store_true", help="with --check, fail while any fragment is pending")
    parser.add_argument("--dry-run", action="store_true", help="print the assembled CHANGELOG instead of writing it")
    args = parser.parse_args(argv)

    paths = fragment_paths(args.fragments_dir)
    fragments, errors = load_fragments(paths)
    if errors:
        print("Invalid changelog fragments:")
        print("\n".join(f"  {error}" for error in errors))
        return 1

    if args.check:
        if args.expect_empty and paths:
            print(f"{len(paths)} changelog fragment(s) not yet assembled; run scripts/assemble_changelog.py --version <version>:")
            print("\n".join(f"  {path.name}" for path in paths))
            return 1
        print(f"OK: {len(paths)} changelog fragment(s) valid.")
        return 0

    if not args.version:
        parser.error("--version is required unless --check is given")
    try:
        updated = assemble(args.changelog.read_text(encoding="utf-8"), fragments, args.version, args.date)
    except FragmentError as exc:
        print(f"Cannot assemble: {exc}")
        return 1

    if args.dry_run:
        sys.stdout.write(updated)
        return 0
    args.changelog.write_text(updated, encoding="utf-8")
    for path in paths:
        path.unlink()
    print(f"Assembled {len(paths)} fragment(s) into '## [{args.version}] - {args.date}'.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
