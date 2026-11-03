"""Literal Airflow DAG/operator declarations and bitshift dependencies, without imports."""

from __future__ import annotations

import ast

from agent_bom.parsers.repository.artifacts import RepositoryReader
from agent_bom.parsers.repository.python_source import import_aliases, literal, symbol


class _Airflow:
    def __init__(self, reader: RepositoryReader, path: str, digest: str, tree: ast.Module):
        self.reader, self.path, self.digest = reader, path, digest
        self.aliases: dict[str, str] = {}
        self.nodes: dict[str, dict] = {}
        self.bindings: dict[str, str] = {}
        self.edges: list[dict] = []

    def declare(self, call: ast.Call, variable: str, parent: str = "") -> str:
        name = symbol(call.func, self.aliases)
        if not name.startswith("airflow."):
            return ""
        keywords = {k.arg: k.value for k in call.keywords if k.arg}
        dag = name.rsplit(".", 1)[-1] == "DAG"
        task = name.endswith("Operator") or name.endswith("Sensor")
        if not dag and not task:
            self.reader.note(self.path, "airflow_call_unresolved")
            return ""
        label = literal(keywords.get("dag_id" if dag else "task_id"))
        if dag and label is None and call.args:
            label = literal(call.args[0])
        dag_reference = keywords.get("dag")
        if not dag and isinstance(dag_reference, ast.Name):
            parent = self.bindings.get(dag_reference.id, "")
        if not label or (not dag and not parent):
            self.reader.note(self.path, "dynamic_airflow_structure")
            return ""
        key = f"airflow:{self.path}:{label}" if dag else f"{parent}:task:{label}"
        if key in self.nodes:
            self.reader.note(self.path, "duplicate_pipeline_identity")
            return ""
        refs = [literal(value) for key, value in keywords.items() if key.endswith("conn_id")]
        if any(ref is None for ref in refs):
            self.reader.note(self.path, "connection_reference_unresolved")
        self.nodes[key] = {
            "key": key,
            "kind": "airflow_dag" if dag else "airflow_task",
            "name": label,
            "path": self.path,
            "digest": self.digest,
            "line": call.lineno,
            "parent": parent if not dag else None,
            "connection_references": sorted({ref for ref in refs if ref}),
        }
        if variable:
            self.bindings[variable] = key
        return key

    def endpoints(self, expr: ast.expr) -> list[str]:
        if isinstance(expr, ast.Name) and expr.id in self.bindings:
            return [self.bindings[expr.id]]
        if isinstance(expr, (ast.List, ast.Tuple)):
            values = [self.endpoints(item) for item in expr.elts]
            return [key for group in values for key in group] if all(values) else []
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.RShift, ast.LShift)):
            left, right = self.endpoints(expr.left), self.endpoints(expr.right)
            if not left or not right or len(left) * len(right) > 100:
                self.reader.note(self.path, "task_dependency_unresolved")
                return []
            for before in left:
                for after in right:
                    source, target = (after, before) if isinstance(expr.op, ast.RShift) else (before, after)
                    if self.nodes[source].get("parent") and self.nodes[source].get("parent") == self.nodes[target].get("parent"):
                        self.edges.append(
                            {
                                "source": source,
                                "target": target,
                                "path": self.path,
                                "line": expr.lineno,
                                "basis": "declared_task_dependency",
                            }
                        )
                    else:
                        self.reader.note(self.path, "task_dependency_unresolved")
            return right
        return []

    def statements(self, body: list[ast.stmt], parent: str = "") -> None:
        for stmt in body:
            if len(self.nodes) >= 1000 or len(self.edges) >= 5000:
                self.reader.note(self.path, "pipeline_structure_limit")
                return
            if isinstance(stmt, (ast.Import, ast.ImportFrom)):
                self.aliases.update(import_aliases(ast.Module(body=[stmt], type_ignores=[])))
            elif isinstance(stmt, ast.With):
                if len(stmt.items) == 1 and isinstance(stmt.items[0].context_expr, ast.Call):
                    item = stmt.items[0]
                    call = stmt.items[0].context_expr
                    variable = item.optional_vars.id if isinstance(item.optional_vars, ast.Name) else ""
                    owner = self.declare(call, variable, parent)
                    if owner and self.nodes[owner]["kind"] == "airflow_dag":
                        self.statements(stmt.body, owner)
                    else:
                        self.reader.note(self.path, "dynamic_airflow_structure")
            elif isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                variable = stmt.targets[0].id
                self.bindings.pop(variable, None)
                if isinstance(stmt.value, ast.Call):
                    self.declare(stmt.value, variable, parent)
                self.aliases.pop(variable, None)
            elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.BinOp):
                if not self.endpoints(stmt.value):
                    self.reader.note(self.path, "task_dependency_unresolved")
            elif isinstance(stmt, (ast.For, ast.While, ast.If, ast.FunctionDef, ast.AsyncFunctionDef, ast.Try, ast.ClassDef)):
                self.reader.note(self.path, "dynamic_airflow_structure")


def airflow_context(reader: RepositoryReader, path: str, digest: str, tree: ast.Module) -> tuple[list[dict], list[dict]]:
    collector = _Airflow(reader, path, digest, tree)
    if not any(value == "airflow" or value.startswith("airflow.") for value in import_aliases(tree).values()):
        return [], []
    collector.statements(tree.body)
    return list(collector.nodes.values()), collector.edges
