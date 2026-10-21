"""Showcase constants shared by demo bootstrap and graph projections."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Literal

ShowcaseProfile = Literal["baseline", "current"]


SHOWCASE_TENANT = "default"


SHOWCASE_SCAN_ID = "showcase"


SHOWCASE_SOURCE = "demo-showcase"


SHOWCASE_BASELINE_SCAN_ID = "showcase-baseline"


# Bumped when the seeded snapshot's *shape or content* changes so
# ``_showcase_seed_is_current`` treats an older seed as stale and refreshes it. A
# DB seeded before the enterprise estate was projected in still holds the
# 112-node showcase; without a bump it would keep it forever and the demo would
# silently under-report. The same applies to what the projection *writes*: the
# 08-01/08-08 pair shipped estate finding nodes whose ``recommendation`` was a
# ``Remediation`` object frozen to its Python repr, and a running demo would have
# served that snapshot forever. The seven-day gap is the drift lens's window and
# is preserved on every bump.
# The October 19 02:00 seed mints one vulnerability node per advisory, every recorded
# package holder, hosted MCP servers and multi-level package trees.
_SHOWCASE_CURRENT_TARGET = datetime(2026, 10, 19, 2, 0, 0, tzinfo=timezone.utc)


_SHOWCASE_IMPORT_NOW = datetime.now(timezone.utc)


# Preserve the deterministic target once it is in the past. Before then, clamp
# to the current UTC day's start so a release candidate never presents a
# snapshot from tomorrow. The seven-day baseline window remains intact.
_SHOWCASE_CURRENT_STAMP = (
    _SHOWCASE_CURRENT_TARGET
    if _SHOWCASE_CURRENT_TARGET <= _SHOWCASE_IMPORT_NOW
    else _SHOWCASE_IMPORT_NOW.replace(hour=0, minute=0, second=0, microsecond=0)
)


SHOWCASE_CURRENT_CREATED_AT = _SHOWCASE_CURRENT_STAMP.isoformat()


SHOWCASE_BASELINE_CREATED_AT = (_SHOWCASE_CURRENT_STAMP - timedelta(days=7)).isoformat()


# The estate's containment root, once projected, becomes the graph's single
# top-level container. The hand-built showcase org hangs off it so the demo reads
# as one estate rather than two unrelated roots.
SHOWCASE_ORG_ID = "org:corp"


# One shared definition for the hand-built vulnerability paths.  The graph
# seeder and the demo scan both consume these records so a path cannot render in
# the graph while the corresponding finding reports unknown reachability.
SHOWCASE_AGENTS: dict[str, str] = {
    "cursor": "Cursor",
    "langchain-service": "LangChain Service",
    "support-copilot": "Support Copilot",
    "data-pipeline": "Data Pipeline",
    "claude-desktop": "Claude Desktop",
}


SHOWCASE_SERVERS: dict[str, tuple[str, list[str]]] = {
    "filesystem-server": ("cursor", ["read_file", "write_file", "list_directory"]),
    "shell-runner-server": ("cursor", ["run_shell", "exec_command", "read_file"]),
    "llm-orchestrator-server": ("langchain-service", ["run_chain", "eval_expression", "http_get"]),
    "vector-db-server": ("langchain-service", ["query_vectors", "upsert_vectors"]),
    "helpdesk-server": ("support-copilot", ["create_ticket", "search_tickets", "send_reply"]),
    "email-server": ("support-copilot", ["send_email", "list_inbox"]),
    "warehouse-server": ("data-pipeline", ["run_query", "execute_sql", "export_csv"]),
    "etl-server": ("data-pipeline", ["transform_image", "load_data"]),
    "github-server": ("claude-desktop", ["create_issue", "search_repos", "push_files"]),
    "team-chat-server": ("claude-desktop", ["send_message", "list_channels"]),
}


SHOWCASE_PACKAGES: dict[str, tuple[str, str, str, float]] = {
    "pyyaml@5.3": ("shell-runner-server", "CVE-2020-14343", "critical", 9.8),
    "langchain@0.0.150": ("llm-orchestrator-server", "CVE-2023-36258", "critical", 9.8),
    "pillow@9.0.0": ("etl-server", "CVE-2023-4863", "high", 8.8),
    "jsonwebtoken@8.5.1": ("helpdesk-server", "CVE-2022-23539", "high", 8.1),
    "axios@1.4.0": ("helpdesk-server", "CVE-2023-45857", "medium", 6.5),
    "cryptography@39.0.0": ("warehouse-server", "CVE-2023-50782", "high", 7.5),
    "ws@8.5.0": ("filesystem-server", "CVE-2024-37890", "high", 7.5),
    "flask@2.2.0": ("team-chat-server", "CVE-2023-30861", "high", 7.5),
    "certifi@2022.12.7": ("email-server", "CVE-2023-37920", "high", 7.5),
    "lodash@4.17.20": ("github-server", "CVE-2021-23337", "high", 7.2),
    "express@4.17.1": ("filesystem-server", "CVE-2024-29041", "medium", 6.1),
    "requests@2.28.0": ("vector-db-server", "CVE-2023-32681", "medium", 6.1),
    "jinja2@3.0.0": ("team-chat-server", "CVE-2024-22195", "medium", 5.4),
    "node-fetch@2.6.1": ("filesystem-server", "CVE-2022-0235", "high", 8.8),
    "werkzeug@2.2.2": ("team-chat-server", "CVE-2023-25577", "high", 7.5),
}
