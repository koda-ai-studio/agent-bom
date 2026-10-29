"""Bounded gzip NDJSON exports to tenant/run-scoped object storage."""

from __future__ import annotations

import gzip
import json
import logging
from collections.abc import Callable, Iterable
from tempfile import SpooledTemporaryFile
from typing import Any

from agent_bom.export.destination_contract import ExportDestinationError, ExportResult

logger = logging.getLogger(__name__)


# Rows spill to disk past this many bytes so upload RAM stays flat regardless of
# how many findings a tenant has.
_SPOOL_MAX_BYTES = 8 * 1024 * 1024


def _object_key(prefix: str, tenant_id: str, run_id: str) -> str:
    """Tenant/run-partitioned object key for an object-store export."""
    safe_tenant = (tenant_id or "default").replace("/", "_").replace("\\", "_")
    clean_prefix = prefix.strip("/")
    name = f"{run_id}.ndjson.gz"
    if clean_prefix:
        return f"{clean_prefix}/tenant={safe_tenant}/{name}"
    return f"tenant={safe_tenant}/{name}"


class S3ObjectStoreDestination:
    """Stream a gzip NDJSON findings snapshot to an S3 object store.

    Uses the ambient boto3 credential chain (IRSA / instance role / brokered
    short-lived creds) — no static access key is held in the trust path. The
    connect-once *connection* stores the non-secret bucket/prefix/region config;
    ``client_factory`` is injectable for tests.
    """

    kind = "s3"

    def __init__(
        self,
        bucket: str,
        *,
        prefix: str = "findings-feed",
        region: str | None = None,
        client_factory: Callable[[], Any] | None = None,
    ) -> None:
        if not bucket:
            raise ExportDestinationError("S3 export destination requires a bucket")
        self._bucket = bucket
        self._prefix = prefix
        self._region = region
        self._client_factory = client_factory or self._default_client_factory

    def _default_client_factory(self) -> Any:
        try:
            import boto3
        except ImportError as exc:  # pragma: no cover - optional extra
            raise ExportDestinationError("S3 export requires boto3; install with: pip install 'agent-bom[aws]'") from exc
        kwargs: dict[str, str] = {}
        if self._region:
            kwargs["region_name"] = self._region
        return boto3.client("s3", **kwargs)

    def write_findings(self, rows: Iterable[dict[str, Any]], *, tenant_id: str, run_id: str) -> ExportResult:
        key = _object_key(self._prefix, tenant_id, run_id)
        row_count = 0
        # SpooledTemporaryFile keeps small exports in RAM but spills to disk past
        # the threshold, so a huge tenant never inflates process memory.
        with SpooledTemporaryFile(max_size=_SPOOL_MAX_BYTES) as spool:
            with gzip.GzipFile(fileobj=spool, mode="wb") as gz:
                for row in rows:
                    line = json.dumps(row, separators=(",", ":"), ensure_ascii=True, default=str)
                    gz.write(line.encode("utf-8"))
                    gz.write(b"\n")
                    row_count += 1
            byte_count = spool.tell()
            spool.seek(0)
            client = self._client_factory()
            client.upload_fileobj(
                spool,
                self._bucket,
                key,
                ExtraArgs={"ContentType": "application/gzip", "ServerSideEncryption": "AES256"},
            )
        uri = f"s3://{self._bucket}/{key}"
        logger.info("Exported %d findings to %s", row_count, uri)
        return ExportResult(kind=self.kind, destination_uri=uri, row_count=row_count, byte_count=byte_count)


def _stream_gzip_ndjson(rows: Iterable[dict[str, Any]], spool: Any) -> int:
    """Write ``rows`` as gzip NDJSON into ``spool`` and return the row count.

    Shared by every object-store adapter so the on-disk snapshot shape is
    byte-identical across s3 / azure-blob / gcs. Streaming: at most one row is
    materialized at a time, so RAM stays flat regardless of tenant size.
    """
    row_count = 0
    with gzip.GzipFile(fileobj=spool, mode="wb") as gz:
        for row in rows:
            line = json.dumps(row, separators=(",", ":"), ensure_ascii=True, default=str)
            gz.write(line.encode("utf-8"))
            gz.write(b"\n")
            row_count += 1
    return row_count


class AzureBlobObjectStoreDestination:
    """Stream a gzip NDJSON findings snapshot to an Azure Blob container.

    Mirrors :class:`S3ObjectStoreDestination`: rows stream through a gzip writer
    backed by a spooled temp file (RAM-bounded, spills to disk past a threshold),
    then the blob is uploaded with ``overwrite=True``. The client is built once
    from the connect-once connection (a stored, encrypted Azure Storage
    connection string, or ambient managed identity against ``account_url``) — no
    per-run credential. ``client_factory`` is injectable for tests.
    """

    kind = "azure-blob"

    def __init__(
        self,
        container: str,
        *,
        prefix: str = "findings-feed",
        client_factory: Callable[[], Any],
    ) -> None:
        if not container:
            raise ExportDestinationError("Azure Blob export destination requires a container")
        self._container = container
        self._prefix = prefix
        self._client_factory = client_factory

    def write_findings(self, rows: Iterable[dict[str, Any]], *, tenant_id: str, run_id: str) -> ExportResult:
        key = _object_key(self._prefix, tenant_id, run_id)
        with SpooledTemporaryFile(max_size=_SPOOL_MAX_BYTES) as spool:
            row_count = _stream_gzip_ndjson(rows, spool)
            byte_count = spool.tell()
            spool.seek(0)
            service = self._client_factory()
            blob = service.get_blob_client(container=self._container, blob=key)
            blob.upload_blob(spool, overwrite=True)
        uri = f"azure-blob://{self._container}/{key}"
        logger.info("Exported %d findings to %s", row_count, uri)
        return ExportResult(kind=self.kind, destination_uri=uri, row_count=row_count, byte_count=byte_count)


class GcsObjectStoreDestination:
    """Stream a gzip NDJSON findings snapshot to a Google Cloud Storage bucket.

    Mirrors :class:`S3ObjectStoreDestination`. The client is built once from the
    connect-once connection (a stored service-account key JSON, or ambient
    Application Default Credentials) — no per-run credential. The blob is uploaded
    from the spooled file object (streamed, not buffered). ``client_factory`` is
    injectable for tests.
    """

    kind = "gcs"

    def __init__(
        self,
        bucket: str,
        *,
        prefix: str = "findings-feed",
        client_factory: Callable[[], Any],
    ) -> None:
        if not bucket:
            raise ExportDestinationError("GCS export destination requires a bucket")
        self._bucket = bucket
        self._prefix = prefix
        self._client_factory = client_factory

    def write_findings(self, rows: Iterable[dict[str, Any]], *, tenant_id: str, run_id: str) -> ExportResult:
        key = _object_key(self._prefix, tenant_id, run_id)
        with SpooledTemporaryFile(max_size=_SPOOL_MAX_BYTES) as spool:
            row_count = _stream_gzip_ndjson(rows, spool)
            byte_count = spool.tell()
            spool.seek(0)
            client = self._client_factory()
            blob = client.bucket(self._bucket).blob(key)
            blob.upload_from_file(spool, content_type="application/gzip", rewind=True)
        uri = f"gs://{self._bucket}/{key}"
        logger.info("Exported %d findings to %s", row_count, uri)
        return ExportResult(kind=self.kind, destination_uri=uri, row_count=row_count, byte_count=byte_count)
