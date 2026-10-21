"""Tenant-scoped dataset version registry for headless API clients."""

from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol

from agent_bom.api.storage.registry_sqlite import SQLiteRegistryStore
from agent_bom.storage.base import BackendKind
from agent_bom.storage.factory import resolve_backend


@dataclass(frozen=True)
class DatasetVersionRecord:
    tenant_id: str
    dataset_id: str
    version_id: str
    created_at: str
    source: str
    artifact_uri: str | None = None
    digest: str | None = None
    digest_algorithm: str = "sha256"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class DatasetVersionStore(Protocol):
    def put(self, record: DatasetVersionRecord) -> None: ...
    def get(self, tenant_id: str, dataset_id: str, version_id: str) -> DatasetVersionRecord | None: ...
    def list(self, tenant_id: str, dataset_id: str) -> list[DatasetVersionRecord]: ...


class InMemoryDatasetVersionStore:
    def __init__(self) -> None:
        self._records: dict[tuple[str, str, str], DatasetVersionRecord] = {}
        self._lock = threading.Lock()

    def put(self, record: DatasetVersionRecord) -> None:
        with self._lock:
            self._records[(record.tenant_id, record.dataset_id, record.version_id)] = record

    def get(self, tenant_id: str, dataset_id: str, version_id: str) -> DatasetVersionRecord | None:
        with self._lock:
            return self._records.get((tenant_id, dataset_id, version_id))

    def list(self, tenant_id: str, dataset_id: str) -> list[DatasetVersionRecord]:
        with self._lock:
            records = [record for record in self._records.values() if record.tenant_id == tenant_id and record.dataset_id == dataset_id]
        return sorted(records, key=lambda record: record.created_at, reverse=True)


class SQLiteDatasetVersionStore(SQLiteRegistryStore[DatasetVersionRecord]):
    table = "dataset_versions"
    columns = ("tenant_id", "dataset_id", "version_id", "created_at")

    ddl = (
        """
            CREATE TABLE IF NOT EXISTS dataset_versions (
                tenant_id TEXT NOT NULL,
                dataset_id TEXT NOT NULL,
                version_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                data TEXT NOT NULL,
                PRIMARY KEY (tenant_id, dataset_id, version_id)
            )
            """,
        "CREATE INDEX IF NOT EXISTS idx_dataset_versions_tenant_dataset_created "
        "ON dataset_versions(tenant_id, dataset_id, created_at DESC)",
    )

    def _decode(self, raw: str) -> DatasetVersionRecord:
        return _record_from_json(raw)

    def put(self, record: DatasetVersionRecord) -> None:
        self._put_payload((record.tenant_id, record.dataset_id, record.version_id, record.created_at), record.to_dict())

    def get(self, tenant_id: str, dataset_id: str, version_id: str) -> DatasetVersionRecord | None:
        return self._get("tenant_id = ? AND dataset_id = ? AND version_id = ?", (tenant_id, dataset_id, version_id))

    def list(self, tenant_id: str, dataset_id: str) -> list[DatasetVersionRecord]:
        return self._list("tenant_id = ? AND dataset_id = ?", (tenant_id, dataset_id), order="created_at DESC")


def _record_from_json(raw: str) -> DatasetVersionRecord:
    payload = json.loads(raw)
    return DatasetVersionRecord(
        tenant_id=str(payload["tenant_id"]),
        dataset_id=str(payload["dataset_id"]),
        version_id=str(payload["version_id"]),
        created_at=str(payload["created_at"]),
        source=str(payload["source"]),
        artifact_uri=payload.get("artifact_uri"),
        digest=payload.get("digest"),
        digest_algorithm=str(payload.get("digest_algorithm") or "sha256"),
        metadata=payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {},
    )


_DATASET_VERSION_STORE: DatasetVersionStore | None = None


def get_dataset_version_store() -> DatasetVersionStore:
    global _DATASET_VERSION_STORE
    if _DATASET_VERSION_STORE is not None:
        return _DATASET_VERSION_STORE
    selection = resolve_backend()
    if selection.backend is BackendKind.POSTGRES:
        from agent_bom.api.storage.registry_stores import PostgresDatasetVersionStore

        _DATASET_VERSION_STORE = PostgresDatasetVersionStore()
    elif selection.backend is BackendKind.SQLITE:
        _DATASET_VERSION_STORE = SQLiteDatasetVersionStore(selection.sqlite_path or "")
    else:
        _DATASET_VERSION_STORE = InMemoryDatasetVersionStore()
    return _DATASET_VERSION_STORE


def set_dataset_version_store(store: DatasetVersionStore | None) -> None:
    global _DATASET_VERSION_STORE
    _DATASET_VERSION_STORE = store


def reset_dataset_version_store() -> None:
    set_dataset_version_store(None)
