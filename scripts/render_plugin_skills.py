#!/usr/bin/env python3
"""Render the agent-bom plugin skills from one shared spec.

``integrations/shared/skills.toml`` holds each skill's description,
capabilities and shared safety rules. From it this script writes:

* the skills-only Codex package skills, ``integrations/codex/skills/*/SKILL.md``,
  which run the pinned CLI from the shell;
* the ``## Rules`` section at the end of every MCP skill in
  ``integrations/claude-code/skills/*/SKILL.md`` (the rest of those files is
  hand-written);
* ``integrations/codex/.codex-plugin/plugin.json``, the Codex-format overlay of
  the portable ``integrations/codex/plugin.json``.

Usage::

    python scripts/render_plugin_skills.py           # rewrite the outputs
    python scripts/render_plugin_skills.py --check   # exit 1 when any output is stale
"""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "integrations" / "shared" / "skills.toml"
CODEX = ROOT / "integrations" / "codex"
CLAUDE = ROOT / "integrations" / "claude-code"
PUBLISHED_VERSION_FILE = ROOT / "PUBLISHED_VERSION"
REPO_URL = "https://github.com/koda-ai-studio/agent-bom"
RULES_HEADING = "## Rules"
CAPABILITY_KEYS = ("read_inventory", "read_findings", "read_audit_log", "write_findings", "outbound_http")
OVERLAY_KEYS = ("name", "version", "description", "author", "homepage", "repository", "license", "keywords")


def load_spec(path: Path = SPEC) -> dict[str, Any]:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def published_version() -> str:
    return PUBLISHED_VERSION_FILE.read_text(encoding="utf-8").strip()


def _fill(text: str, release: str) -> str:
    return text.replace("{ab}", f"uvx --from agent-bom=={release} agent-bom").replace("{release}", release)


def rules_section(spec: dict[str, Any]) -> str:
    bullets = "\n".join(f"- {rule}" for rule in spec["rules"].values())
    return f"{RULES_HEADING}\n\n{bullets}\n"


def _yaml_bool(value: bool) -> str:
    return "true" if value else "false"


def codex_frontmatter(job: str, skill: dict[str, Any]) -> str:
    caps = skill["capabilities"]
    missing = [key for key in CAPABILITY_KEYS if key not in caps]
    if missing:
        raise ValueError(f"{job}: capabilities missing {missing}")
    lines = [
        "---",
        f"name: {job}",
        f"description: {skill['description']}",
        f"homepage: {REPO_URL}",
        f"source: {REPO_URL}/tree/main/integrations/codex/skills/{job}",
        "license: Apache-2.0",
        "capabilities:",
    ]
    # Every Codex skill runs the CLI through uvx, which fetches the pinned release
    # from PyPI, so shell execution and outbound HTTP are always declared.
    declared = {**{key: caps[key] for key in CAPABILITY_KEYS}, "outbound_http": True, "shell_exec": True}
    lines += [f"  {key}: {_yaml_bool(value)}" for key, value in declared.items()]
    lines += ["requires:", "  bins:", "    - uvx"]
    optional = skill.get("optional_bins") or []
    if optional:
        lines += ["optional_bins:", *[f"  - {name}" for name in optional]]
    lines.append("---")
    return "\n".join(lines) + "\n"


def render_codex_skill(job: str, spec: dict[str, Any], release: str) -> str:
    skill = spec["skills"][job]
    body = _fill(skill["codex_body"].strip(), release)
    running = _fill(spec["codex"]["running"].strip(), release)
    return f"{codex_frontmatter(job, skill)}\n{body}\n\n## Running agent-bom\n\n{running}\n\n{rules_section(spec)}"


def render_claude_skill(current: str, spec: dict[str, Any]) -> str:
    head = current.split(f"\n{RULES_HEADING}\n", 1)[0].rstrip()
    return f"{head}\n\n{rules_section(spec)}"


def render_overlay(root_manifest: dict[str, Any]) -> str:
    overlay = {key: root_manifest[key] for key in OVERLAY_KEYS if key in root_manifest}
    overlay["skills"] = "./skills/"
    overlay["interface"] = root_manifest["extensions"]["com.openai"]["interface"]
    return json.dumps(overlay, indent=2, ensure_ascii=False) + "\n"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.exists() else ""


def render_all(spec: dict[str, Any] | None = None, release: str | None = None) -> dict[Path, str]:
    """Return every rendered output keyed by its path."""
    spec = spec or load_spec()
    release = release or published_version()
    outputs: dict[Path, str] = {}
    for job in sorted(spec["skills"]):
        outputs[CODEX / "skills" / job / "SKILL.md"] = render_codex_skill(job, spec, release)
        claude_path = CLAUDE / "skills" / job / "SKILL.md"
        outputs[claude_path] = render_claude_skill(_read(claude_path), spec)
    root_manifest = json.loads(_read(CODEX / "plugin.json"))
    outputs[CODEX / ".codex-plugin" / "plugin.json"] = render_overlay(root_manifest)
    return outputs


def stale_paths(outputs: dict[Path, str], read: Callable[[Path], str] = _read) -> list[Path]:
    return sorted(path for path, text in outputs.items() if read(path) != text)


def consistency_errors(spec: dict[str, Any]) -> list[str]:
    """Spec descriptions must match the hand-written MCP skill frontmatter."""
    errors: list[str] = []
    claude_jobs = sorted(path.parent.name for path in (CLAUDE / "skills").glob("*/SKILL.md"))
    if claude_jobs != sorted(spec["skills"]):
        errors.append(f"spec skills {sorted(spec['skills'])} != MCP skills {claude_jobs}")
    for job, skill in spec["skills"].items():
        text = _read(CLAUDE / "skills" / job / "SKILL.md")
        if f"\ndescription: {skill['description']}\n" not in text:
            errors.append(f"{job}: description differs from integrations/claude-code/skills/{job}/SKILL.md")
        for key in CAPABILITY_KEYS:
            if key == "outbound_http":
                continue
            if f"\n  {key}: {_yaml_bool(skill['capabilities'][key])}\n" not in text:
                errors.append(f"{job}: capability {key} differs from the MCP skill")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 when any rendered output is stale")
    args = parser.parse_args(argv)

    spec = load_spec()
    errors = consistency_errors(spec)
    if errors:
        print("render_plugin_skills: spec and MCP skills disagree:", file=sys.stderr)
        print("\n".join(f"  - {error}" for error in errors), file=sys.stderr)
        return 1
    outputs = render_all(spec)
    stale = stale_paths(outputs)
    if args.check:
        if stale:
            print("render_plugin_skills: stale outputs; run `python scripts/render_plugin_skills.py`:", file=sys.stderr)
            print("\n".join(f"  - {path.relative_to(ROOT)}" for path in stale), file=sys.stderr)
            return 1
        return 0
    for path in stale:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(outputs[path], encoding="utf-8")
        print(f"wrote {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
