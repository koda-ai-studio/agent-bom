"""Read an explicit bounded snapshot; no bucket discovery, writes or polling."""

from __future__ import annotations

import hashlib
import io
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

MAX_BYTES = 16 * 1024 * 1024


def _bounded_read(stream) -> bytes:
    data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("Lake input exceeds 16 MiB")
    return data


def read_lake_snapshot(source: str, *, version_id: str | None = None, expected_owner: str | None = None) -> tuple[bytes, dict]:
    """Pin S3 reads to an explicit version and owner through the existing AWS credential chain."""
    if not source.startswith("s3://"):
        if "://" in source or version_id or expected_owner:
            raise ValueError("Use a local file or a version-pinned S3 object")
        with Path(source).open("rb") as stream:
            return _bounded_read(stream), {"kind": "local_export"}
    parsed = urlsplit(source)
    if (
        not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", parsed.netloc)
        or not parsed.path.strip("/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Invalid S3 object reference")
    if not version_id or version_id == "null" or not expected_owner or not re.fullmatch(r"[0-9]{12}", expected_owner):
        raise ValueError("S3 requires a non-null version ID and expected bucket owner")
    import boto3
    from botocore import exceptions
    from botocore.config import Config

    client = None
    try:
        client = boto3.client("s3", config=Config(connect_timeout=5, read_timeout=20, retries={"total_max_attempts": 2}))
        response = client.get_object(Bucket=parsed.netloc, Key=parsed.path[1:], VersionId=version_id, ExpectedBucketOwner=expected_owner)
        stream = response["Body"]
        try:
            if response.get("VersionId") != version_id or response.get("ContentLength", MAX_BYTES + 1) > MAX_BYTES:
                raise ValueError("Object version mismatch or size limit exceeded")
            data = _bounded_read(stream)
            if len(data) != response["ContentLength"]:
                raise ValueError("Incomplete lake object")
        finally:
            stream.close()
    except (exceptions.BotoCoreError, exceptions.ClientError):
        raise ValueError("Cannot read the pinned lake object") from None
    finally:
        if client is not None:
            client.close()
    return data, {
        "kind": "s3_object",
        "bucket": parsed.netloc,
        "object_path": parsed.path[1:],
        "version_id": version_id,
        "owner": expected_owner,
    }


def decode_lake_snapshot(data: bytes, *, input_format: str) -> tuple[list[dict], str]:
    """Bound input before JSON decoding; reject invalid rows rather than skip them."""
    if len(data) > MAX_BYTES:
        raise ValueError("Lake input exceeds 16 MiB")
    if input_format == "json":
        rows = json.loads(data)
    elif input_format == "ndjson":
        rows = []
        for line in io.BytesIO(data):
            if line.strip():
                if len(rows) >= 1000:
                    raise ValueError("Lake row limit exceeded")
                rows.append(json.loads(line))
    else:
        raise ValueError("Unsupported lake encoding")
    if not isinstance(rows, list):
        raise ValueError("Lake snapshot must be a JSON array of findings")
    return rows, hashlib.sha256(data).hexdigest()
