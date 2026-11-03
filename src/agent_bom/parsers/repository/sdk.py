"""Static Python SDK calls under lexical aliases; never evaluates values or executes code."""
# ruff: noqa: N815 -- ast.NodeVisitor dispatch requires these mixed-case protocol names.

from __future__ import annotations

import ast

from agent_bom.parsers.repository.artifacts import RepositoryReader
from agent_bom.parsers.repository.python_source import symbol
from agent_bom.parsers.repository.sdk_imports import AGENT_FACTORIES, imported_rows, is_sdk, workspace_boundary


class _Collector(ast.NodeVisitor):
    def __init__(self, reader: RepositoryReader, path: str, files: set[str], boundary: str):
        self.reader, self.path, self.files, self.boundary = reader, path, files, boundary
        self.aliases: dict[str, str] = {}
        self.imports: list[dict] = []
        self.calls: list[dict] = []
        self.implementations: list[dict] = []

    def visit_Import(self, node: ast.Import | ast.ImportFrom) -> None:
        for alias in node.names:
            self.aliases.pop(alias.asname or (alias.name.split(".")[0] if isinstance(node, ast.Import) else alias.name), None)
        for row in imported_rows(self.reader, self.path, node, self.files, self.boundary):
            if len(self.imports) >= 64:
                self.reader.note(self.path, "import_limit")
                break
            self.imports.append(row)
            self.aliases.pop(row["alias"], None)
            if row.get("symbol"):
                self.aliases[row["alias"]] = row["symbol"]

    visit_ImportFrom = visit_Import

    def visit_Call(self, node: ast.Call) -> None:
        name = symbol(node.func, self.aliases)
        if name and is_sdk(name):
            if len(self.calls) < 100:
                self.calls.append({"symbol": name, "line": node.lineno, "evidence": "static_call_expression"})
            else:
                self.reader.note(self.path, "call_limit")
        if (isinstance(node.func, ast.Name) and node.func.id == "__import__") or (
            isinstance(node.func, ast.Attribute) and node.func.attr == "import_module"
        ):
            self.reader.note(self.path, "dynamic_import_unresolved")
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        resolved = symbol(node.value.func, self.aliases) if isinstance(node.value, ast.Call) else symbol(node.value, self.aliases)
        self.visit(node.value)
        for target in node.targets:
            for name in ast.walk(target):
                if isinstance(name, ast.Name):
                    self.aliases.pop(name.id, None)
        constructor = resolved.rsplit(".", 1)[-1][:1].isupper() or resolved in {"boto3.client", "boto3.resource", *AGENT_FACTORIES}
        if (
            len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and is_sdk(resolved)
            and (not isinstance(node.value, ast.Call) or constructor)
        ):
            variable = node.targets[0].id
            self.aliases[variable] = resolved
            if resolved in AGENT_FACTORIES and isinstance(node.value, ast.Call):
                self.implementations.append({"name": variable, "symbol": resolved, "line": node.lineno})

    def visit_AnnAssign(self, node: ast.AnnAssign | ast.AugAssign) -> None:
        if node.value:
            self.visit(node.value)
        if isinstance(node.target, ast.Name):
            self.aliases.pop(node.target.id, None)

    visit_AugAssign = visit_AnnAssign

    def visit_Delete(self, node: ast.Delete) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.aliases.pop(target.id, None)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        if isinstance(node.target, ast.Name):
            self.aliases.pop(node.target.id, None)

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        outer = self.aliases
        self.aliases = dict(outer)
        # Python treats any assigned/imported name in a function as local for its entire body.
        locals_ = {
            item.id for stmt in node.body for item in ast.walk(stmt) if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Store)
        }
        locals_.update(arg.arg for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs])
        locals_.update(arg.arg for arg in (node.args.vararg, node.args.kwarg) if arg is not None)
        for stmt in node.body:
            for item in ast.walk(stmt):
                if isinstance(item, (ast.Import, ast.ImportFrom)):
                    locals_.update(
                        alias.asname or (alias.name.split(".")[0] if isinstance(item, ast.Import) else alias.name) for alias in item.names
                    )
        for name in locals_:
            self.aliases.pop(name, None)
        for stmt in node.body:
            self.visit(stmt)
        self.aliases = outer
        self.aliases.pop(node.name, None)

    visit_AsyncFunctionDef = visit_FunctionDef

    def _dynamic(self, node: ast.AST) -> None:
        self.reader.note(self.path, "dynamic_code_structure")
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                self.aliases.pop(child.id, None)
            elif isinstance(child, (ast.Import, ast.ImportFrom)):
                for alias in child.names:
                    self.aliases.pop(alias.asname or (alias.name.split(".")[0] if isinstance(child, ast.Import) else alias.name), None)
        if isinstance(node, ast.ClassDef):
            self.aliases.pop(node.name, None)

    visit_If = _dynamic
    visit_For = _dynamic
    visit_AsyncFor = _dynamic
    visit_While = _dynamic
    visit_Try = _dynamic
    visit_TryStar = _dynamic
    visit_With = _dynamic
    visit_AsyncWith = _dynamic
    visit_ClassDef = _dynamic
    visit_Lambda = _dynamic
    visit_ListComp = _dynamic
    visit_DictComp = _dynamic
    visit_SetComp = _dynamic
    visit_GeneratorExp = _dynamic
    visit_Match = _dynamic


def sdk_context(reader: RepositoryReader, path: str, digest: str, tree: ast.Module, files: set[str], packages: list[dict]) -> dict | None:
    # Files without a named SDK import do not enter this narrow static adapter.
    if not any(
        isinstance(node, (ast.Import, ast.ImportFrom))
        and any(is_sdk(node.module or alias.name if isinstance(node, ast.ImportFrom) else alias.name) for alias in node.names)
        for node in ast.walk(tree)
    ):
        return None
    collector = _Collector(reader, path, files, workspace_boundary(path, packages))
    collector.visit(tree)
    return {
        "path": path,
        "digest": digest,
        "imports": collector.imports,
        "calls": collector.calls,
        "implementations": collector.implementations,
        "evidence_tier": "static_scan",
    }
