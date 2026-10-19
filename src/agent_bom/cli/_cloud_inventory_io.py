"""Private credentials and atomic evidence artifacts for cloud collectors."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path

from agent_bom.cloud.connector_push import connector_push_payloads


class CollectionScopeMismatchError(ValueError):
    """A safe, actionable rejection that never includes tenant or resource IDs."""

    def __init__(self) -> None:
        super().__init__("Collection scope changed; use a separate graph database")


def _write_report(path: Path, report: dict) -> None:
    """Publish the complete normalized artifact atomically, with private mode."""
    report["evidence_sha256"] = hashlib.sha256(
        json.dumps({key: value for key, value in report.items() if key != "evidence_sha256"}, sort_keys=True).encode()
    ).hexdigest()
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, prefix=".cloud-evidence-", delete=False) as stream:
            temporary = stream.name
            json.dump(report, stream, indent=2)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)


def read_token(token_file: Path, output: Path, graph_db: Path | None) -> str:
    """Validate private credentials and prevent artifact/credential collisions."""
    if token_file.stat().st_size > 65536:
        raise ValueError("Token file is too large")
    if os.name != "nt" and token_file.stat().st_mode & 0o077:
        raise ValueError("Token file must be private (chmod 600)")
    paths = [token_file.resolve(), output.resolve()]
    if graph_db is not None:
        paths.append(graph_db.resolve())
    if len(set(paths)) != len(paths):
        raise ValueError("Credential, output and graph files must differ")
    credential = json.loads(token_file.read_text())
    if not isinstance(credential, dict) or not isinstance(credential.get("token"), str):
        raise ValueError("Token file must contain a token string")
    return credential["token"]


def persist_graph(
    report: dict, graph_db: Path, tenant: str, output: Path, *, scope_entity_types: set[str], scope_node_ids: set[str]
) -> None:
    """Atomically reject scope changes and record actual snapshot persistence."""
    from agent_bom.db.graph_store import load_graph, open_graph_db, save_graph
    from agent_bom.graph.builder import build_unified_graph_from_report

    try:
        graph_db.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(graph_db, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(descriptor)
        if os.name != "nt" and graph_db.stat().st_mode & 0o077:
            raise ValueError("Graph database must be private (chmod 600)")
        for receipt in report["coverage"]:
            receipt["persisted"] = receipt["complete"]
        graph = build_unified_graph_from_report(report, scan_id=report["scan_id"], tenant_id=tenant)
        with open_graph_db(graph_db) as conn:
            conn.execute("BEGIN IMMEDIATE")
            previous = load_graph(conn, tenant_id=tenant, entity_types=scope_entity_types)
            if previous.scan_id and set(previous.nodes) != scope_node_ids:
                raise CollectionScopeMismatchError()
            save_graph(conn, graph)
    except Exception:
        for receipt in report["coverage"]:
            receipt["persisted"] = False
            receipt["correlated"] = False
        report["persistence"] = {"graph": "failed"}
        _write_report(output, report)
        raise
    report["persistence"] = {"graph": "persisted", "tenant_id": tenant, "scan_id": graph.scan_id}
    _write_report(output, report)


class ConnectorPushError(RuntimeError):
    """The control plane did not accept every connector target."""

    def __init__(self) -> None:
        super().__init__("Push to the control plane failed; the local report records which targets were stored")


def push_report(report: dict, push_url: str, api_key: str | None, output: Path) -> None:
    """Push each explicit connector target to the control plane's result-push path.

    Partial collection is pushed too: its scan run is marked partial, so the
    control plane keeps that target's earlier evidence and reports partial coverage.
    """
    from agent_bom import push

    url = push.normalize_scan_push_url(push_url)
    receipts = []
    for payload in connector_push_payloads(report):
        body = push.push_json(url, payload, api_key, source_id=payload["source_id"])
        receipts.append(
            {
                "source_id": payload["source_id"],
                "target_scope": payload["target_scope"],
                "stored": body is not None,
                "job_id": (body or {}).get("job_id"),
                "scan_outcome": (body or {}).get("scan_outcome"),
            }
        )
    stored = all(receipt["stored"] for receipt in receipts)
    report.setdefault("persistence", {})["push"] = {"status": "pushed" if stored else "failed", "receipts": receipts}
    _write_report(output, report)
    if not stored:
        raise ConnectorPushError()
