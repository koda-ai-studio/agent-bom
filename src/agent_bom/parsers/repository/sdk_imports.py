"""Narrow Python import resolution within the recorded local workspace boundary."""

from __future__ import annotations

import ast
import posixpath

from agent_bom.parsers.repository.artifacts import RepositoryReader

SDK_ROOTS = {
    "openai",
    "anthropic",
    "mcp",
    "agents",
    "crewai",
    "autogen",
    "langgraph",
    "langchain",
    "langchain_openai",
    "langchain_anthropic",
    "boto3",
    "botocore",
    "azure",
    "google",
    "vertexai",
    "snowflake",
    "databricks",
}
AGENT_FACTORIES = {
    "agents.Agent",
    "crewai.Agent",
    "autogen.AssistantAgent",
    "autogen.ConversableAgent",
    "langchain.agents.create_agent",
    "langgraph.prebuilt.create_react_agent",
}


def is_sdk(name: str) -> bool:
    return name.split(".")[0] in SDK_ROOTS


def workspace_boundary(path: str, packages: list[dict]) -> str:
    matches = [
        row["path"] for row in packages if isinstance(row.get("path"), str) and (row["path"] == "." or path.startswith(row["path"] + "/"))
    ]
    return max(matches, key=len) if matches else "."


def local_import(reader: RepositoryReader, path: str, module: str, level: int, files: set[str], boundary: str) -> str | None:
    base = posixpath.dirname(path) if level else ("" if boundary == "." else boundary)
    for _ in range(max(0, level - 1)):
        if not base:
            reader.note(path, "local_import_outside_workspace")
            return None
        base = posixpath.dirname(base)
    candidate = posixpath.join(base, module.replace(".", "/"))
    if boundary != "." and not (candidate == boundary or candidate.startswith(boundary + "/")):
        reader.note(path, "local_import_outside_workspace")
        return None
    matches = [name for name in (candidate + ".py", posixpath.join(candidate, "__init__.py")) if name in files]
    if len(matches) != 1:
        if level:
            reader.note(path, "local_import_unresolved")
        return None
    return matches[0]


def imported_rows(reader: RepositoryReader, path: str, node: ast.Import | ast.ImportFrom, files: set[str], boundary: str) -> list[dict]:
    rows = []
    for alias in node.names[:64]:
        if alias.name == "*":
            reader.note(path, "wildcard_import_unresolved")
            continue
        if isinstance(node, ast.Import):
            name, module, level = alias.name, alias.name, 0
            binding = alias.asname or alias.name.split(".")[0]
            resolved = name if alias.asname else name.split(".")[0]
        else:
            module, level = node.module or alias.name, node.level
            name = f"{node.module}.{alias.name}" if node.module else alias.name
            binding, resolved = alias.asname or alias.name, name
        target = local_import(reader, path, module, level, files, boundary)
        # A local openai.py shadows the SDK. Only explicitly external roots qualify.
        if target:
            rows.append({"module": module, "alias": binding, "target_path": target, "line": node.lineno})
        elif not level and is_sdk(name):
            rows.append({"module": name, "alias": binding, "symbol": resolved, "line": node.lineno})
    return rows
