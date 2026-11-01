"""Capability matrix for docs/VENDOR_COVERAGE: what each scanner lane covers, counted from code.

Imported by ``generate_vendor_coverage.py``; every count is read with the
generator's ``ast`` helpers (passed in as ``gen``) so the table cannot drift
from the rule registries, parser tables and pattern lists it describes.
Rows that name a gap ("not provided") are kept so the document states what
agent-bom does not do.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_P_PARSERS = "src/agent_bom/parsers/__init__.py"
_P_RUNTIME_PATTERNS = "src/agent_bom/runtime/patterns.py"
_P_FILE_SECRETS = "src/agent_bom/scanners/secret_lines.py"
_P_PY_TAINT = "src/agent_bom/ast_python_analysis.py"
_P_JS_TS = "src/agent_bom/ast/js_ts/*.py"
_P_GO = "src/agent_bom/ast_go.py"
_P_SARIF_IMPORT = "src/agent_bom/parsers/sarif.py"
_P_TF_RULES = "src/agent_bom/iac/terraform_security*.py"
_P_MCP_RULES = "src/agent_bom/mcp_tool_rules.py"
_P_MCP_INTROSPECT = "src/agent_bom/mcp_introspect.py"
_P_DB_SYNC = "src/agent_bom/db/sync.py"
_P_BENCH_JSON = "src/agent_bom/cloud/benchmark_inventory.json"

_OS_PACKAGE_DBS = {"apk": "Alpine (apk)", "dpkg": "Debian/Ubuntu (dpkg)", "rpm": "RPM-based (rpm)"}
_TF_RULE_RE = re.compile(r'rule_id="(TF-SEC-\d{3})"')
_MCP_RULE_RE = re.compile(r'rule_id="(MCP-TOOL-\d+)')
_FLOW_CATEGORY_RE = re.compile(r'category="((?:js_ts|go)_[a-z_]+)"')
_TF_PROVIDER_BY_MODULE = (("_azure_", "azure"), ("_gcp_", "gcp"))


def _list_len(gen: Any, path: str, name: str) -> int:
    node = gen._assignment(path, name)
    if not hasattr(node, "elts"):
        raise SystemExit(f"{path}: {name} is not a list/tuple literal")
    return len(node.elts)


def _terraform_rules_by_provider(gen: Any) -> dict[str, list[str]]:
    """Rule ids per cloud provider, attributed by the rule module that defines them."""
    out: dict[str, set[str]] = {"aws": set(), "azure": set(), "gcp": set()}
    for path in gen._glob(_P_TF_RULES):
        provider = next((p for marker, p in _TF_PROVIDER_BY_MODULE if marker in Path(path).name), "aws")
        text = (gen.ROOT / path).read_text(encoding="utf-8")
        out[provider].update(_TF_RULE_RE.findall(text))
    # Provider-agnostic rules (secrets, SSH keys) live in the AWS-era modules but fire on every provider.
    return {provider: sorted(ids) for provider, ids in out.items()}


def _flow_categories(gen: Any) -> dict[str, list[str]]:
    python = gen._dict_keys(_P_PY_TAINT, "_TAINT_SINK_TITLES")
    others: dict[str, set[str]] = {"js_ts": set(), "go": set()}
    for path in [*gen._glob(_P_JS_TS), _P_GO]:
        for category in _FLOW_CATEGORY_RE.findall((gen.ROOT / path).read_text(encoding="utf-8")):
            others["go" if category.startswith("go_") else "js_ts"].add(category)
    return {"python": python, "js_ts": sorted(others["js_ts"]), "go": sorted(others["go"])}


def _row(row_id: str, title: str, status: str, detail: str, values: Any, sources: list[dict[str, str]]) -> dict[str, Any]:
    return {"id": row_id, "title": title, "status": status, "detail": detail, "values": values, "sources": sources}


def build_capabilities(gen: Any) -> list[dict[str, Any]]:  # noqa: PLR0915 - one row per capability, declarative
    rows: list[dict[str, Any]] = []

    parsers = gen._dict_keys(_P_PARSERS, "_BUILTIN_INVENTORY_PARSERS")
    ecosystems = [p for p in parsers if p not in _OS_PACKAGE_DBS]
    rows.append(
        _row(
            "sca",
            "SCA (dependencies)",
            "provided",
            f"{len(ecosystems)} manifest/lockfile parsers: {', '.join(ecosystems)}",
            ecosystems,
            [gen._src(_P_PARSERS, "_BUILTIN_INVENTORY_PARSERS")],
        )
    )

    credential = _list_len(gen, _P_RUNTIME_PATTERNS, "CREDENTIAL_PATTERNS")
    pii = _list_len(gen, _P_RUNTIME_PATTERNS, "PII_PATTERNS")
    file_secrets = _list_len(gen, _P_FILE_SECRETS, "FILE_SECRET_PATTERNS")
    rows.append(
        _row(
            "secrets",
            "Secrets",
            "provided",
            f"{credential} credential patterns, {file_secrets} secret-file patterns, {pii} PII patterns; values are never echoed",
            {"credential_patterns": credential, "file_patterns": file_secrets, "pii_patterns": pii},
            [gen._src(_P_RUNTIME_PATTERNS, "CREDENTIAL_PATTERNS, PII_PATTERNS"), gen._src(_P_FILE_SECRETS, "FILE_SECRET_PATTERNS")],
        )
    )

    flows = _flow_categories(gen)
    rows.append(
        _row(
            "sast_native",
            "SAST (native)",
            "provided",
            f"Python interprocedural taint with {len(flows['python'])} sink classes; "
            f"JS/TS {len(flows['js_ts'])} and Go {len(flows['go'])} dangerous-sink flow categories. "
            "Findings carry severity, CWE and (for LLM prompt sinks) OWASP LLM01.",
            flows,
            [
                gen._src(_P_PY_TAINT, "_TAINT_SINK_TITLES"),
                gen._src(_P_JS_TS, 'category="js_ts_*" literals', "regex"),
                gen._src(_P_GO, 'category="go_*"', "regex"),
            ],
        )
    )

    importers = sorted(str(i["name"]) for i in gen._importers())
    rows.append(
        _row(
            "sast_import",
            "SAST (imported)",
            "provided",
            f"SARIF import via --external-scan plus {len(importers)} third-party report importers",
            {"sarif_import": (gen.ROOT / _P_SARIF_IMPORT).is_file(), "importers": importers},
            [
                gen._src(_P_SARIF_IMPORT, "module file", "file-exists"),
                gen._src("src/agent_bom/parsers/importers/*.py", "ImporterManifest(...)"),
            ],
        )
    )

    tf = _terraform_rules_by_provider(gen)
    families = gen._iac_rule_families()
    other_iac = {k: v for k, v in families.items() if k not in {"TF-SEC"}}
    rows.append(
        _row(
            "iac",
            "IaC misconfiguration",
            "provided",
            f"Terraform: AWS {len(tf['aws'])}, Azure {len(tf['azure'])}, GCP {len(tf['gcp'])} rules (CIS ids per provider); "
            "other families: " + ", ".join(f"{k} {v}" for k, v in other_iac.items()),
            {"terraform": {k: len(v) for k, v in tf.items()}, "terraform_rule_ids": tf, "other_families": other_iac},
            [
                gen._src(_P_TF_RULES, 'rule_id="TF-SEC-NNN" literals by module', "regex"),
                gen._src("src/agent_bom/iac/**/*.py", "rule-id literals", "ast-scan"),
            ],
        )
    )

    mcp_rules = sorted(set(_MCP_RULE_RE.findall((gen.ROOT / _P_MCP_RULES).read_text(encoding="utf-8"))))
    rows.append(
        _row(
            "mcp_audit",
            "MCP server audit",
            "provided",
            f"{len(mcp_rules)} static tool-schema rules plus live tools/list introspection (mcp introspect, mcp audit --live). "
            "Tool-description poisoning heuristics are limited to the prompt-injection patterns in prompt_scanner.",
            {"schema_rules": mcp_rules, "live_introspection": (gen.ROOT / _P_MCP_INTROSPECT).is_file()},
            [gen._src(_P_MCP_RULES, 'rule_id="MCP-TOOL-NN-*"', "regex"), gen._src(_P_MCP_INTROSPECT, "module file", "file-exists")],
        )
    )

    os_dbs = [p for p in parsers if p in _OS_PACKAGE_DBS]
    feeds = gen._strings(_P_DB_SYNC, "DEFAULT_SYNC_SOURCES")
    distro_feeds = [f for f in feeds if f in {"alpine", "debian"}]
    rows.append(
        _row(
            "image_cve",
            "Container image CVE",
            "provided",
            "OS package databases: "
            + ", ".join(_OS_PACKAGE_DBS[p] for p in os_dbs)
            + f"; distro advisory feeds synced: {', '.join(distro_feeds)} (OSV for the rest)",
            {"os_package_dbs": os_dbs, "distro_feeds": distro_feeds},
            [gen._src(_P_PARSERS, "_BUILTIN_INVENTORY_PARSERS"), gen._src(_P_DB_SYNC, "DEFAULT_SYNC_SOURCES")],
        )
    )

    inventory = json.loads((gen.ROOT / _P_BENCH_JSON).read_text(encoding="utf-8"))["providers"]
    live = {p: inventory[p]["implemented_control_count"] for p in sorted(inventory)}
    rows.append(
        _row(
            "cloud_posture_live",
            "Cloud posture (live, API)",
            "provided",
            "Benchmark checks against the provider API: " + ", ".join(f"{p} {n}" for p, n in live.items()),
            live,
            [gen._src(_P_BENCH_JSON, "providers[*].implemented_control_count", "json")],
        )
    )
    rows.append(
        _row(
            "cloud_posture_static",
            "Cloud posture (static IaC)",
            "provided",
            f"Terraform AWS {len(tf['aws'])} / Azure {len(tf['azure'])} / GCP {len(tf['gcp'])}; "
            f"CloudFormation {families.get('CFN', 0)} (AWS)",
            {"terraform": {k: len(v) for k, v in tf.items()}, "cloudformation": families.get("CFN", 0)},
            [gen._src(_P_TF_RULES, 'rule_id="TF-SEC-NNN" literals by module', "regex")],
        )
    )

    dast_modules = gen._glob("src/agent_bom/**/dast*.py")
    rows.append(
        _row(
            "dast_http",
            "HTTP/API dynamic testing (DAST)",
            "not provided" if not dast_modules else "provided",
            "No HTTP/API/web dynamic testing. Live MCP audit introspects tool schemas; it does not fuzz or probe endpoints.",
            dast_modules,
            [gen._src("src/agent_bom/**/dast*.py", "module files", "glob")],
        )
    )
    return rows


def render_capabilities(rows: list[dict[str, Any]]) -> list[str]:
    lines = [
        "## Capability matrix",
        "",
        "What each scanner lane covers, counted from the rule registries, parser",
        "tables and pattern lists named in the Source column. `not provided` rows are",
        "deliberate: they state what agent-bom does not do.",
        "",
        "| Capability | Status | Coverage | Source |",
        "|---|---|---|---|",
    ]
    for row in rows:
        sources = "; ".join(f"`{s['path']}` `{s['symbol']}`" for s in row["sources"])
        lines.append(f"| {row['title']} | {row['status']} | {row['detail']} | {sources} |")
    return lines
