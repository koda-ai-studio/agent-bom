"""Object reads are bounded, pinned, explicit and read-only without AWS extras."""

from __future__ import annotations

import io
import json
import sys
from types import SimpleNamespace

import pytest

from agent_bom.connectors.lake_snapshot import MAX_BYTES, decode_lake_snapshot, read_lake_snapshot


@pytest.fixture(autouse=True)
def fake_aws_exceptions(monkeypatch):
    exceptions = SimpleNamespace(BotoCoreError=RuntimeError, ClientError=RuntimeError)
    monkeypatch.setitem(sys.modules, "botocore", SimpleNamespace(exceptions=exceptions))


@pytest.mark.parametrize("version,owner", [(None, None), ("null", "123456789012"), ("v1", "bad")])
def test_s3_rejects_unpinned_reads_before_sdk(version, owner):
    with pytest.raises(ValueError):
        read_lake_snapshot("s3://sample-lake/findings.json", version_id=version, expected_owner=owner)


def test_exact_s3_read_closes_stream_and_client(monkeypatch):
    calls = []
    stream = io.BytesIO(b"[]")
    client = SimpleNamespace(
        get_object=lambda **kw: calls.append(kw) or {"Body": stream, "VersionId": "v1", "ContentLength": 2},
        close=lambda: calls.append("closed"),
    )
    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace(client=lambda *a, **kw: client))
    monkeypatch.setitem(sys.modules, "botocore.config", SimpleNamespace(Config=lambda **kw: kw))
    data, receipt = read_lake_snapshot("s3://sample-lake/findings.json", version_id="v1", expected_owner="123456789012")
    assert data == b"[]" and receipt["version_id"] == "v1"
    assert calls == [{"Bucket": "sample-lake", "Key": "findings.json", "VersionId": "v1", "ExpectedBucketOwner": "123456789012"}, "closed"]
    assert stream.closed


@pytest.mark.parametrize("size,version", [(MAX_BYTES + 1, "v1"), (2, "different")])
def test_s3_rejects_oversize_or_mismatched_version(monkeypatch, size, version):
    stream = io.BytesIO(b"[]")
    client = SimpleNamespace(get_object=lambda **kw: {"Body": stream, "VersionId": version, "ContentLength": size}, close=lambda: None)
    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace(client=lambda *a, **kw: client))
    monkeypatch.setitem(sys.modules, "botocore.config", SimpleNamespace(Config=lambda **kw: kw))
    with pytest.raises(ValueError):
        read_lake_snapshot("s3://sample-lake/findings.json", version_id="v1", expected_owner="123456789012")
    assert stream.closed


def test_byte_limit_enforced_even_when_content_length_lies(monkeypatch):
    stream = io.BytesIO(b" " * (MAX_BYTES + 1))
    client = SimpleNamespace(get_object=lambda **kw: {"Body": stream, "VersionId": "v1", "ContentLength": 2}, close=lambda: None)
    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace(client=lambda *a, **kw: client))
    monkeypatch.setitem(sys.modules, "botocore.config", SimpleNamespace(Config=lambda **kw: kw))
    with pytest.raises(ValueError):
        read_lake_snapshot("s3://sample-lake/findings.json", version_id="v1", expected_owner="123456789012")
    assert stream.closed


def test_ndjson_is_not_silently_truncated():
    rows, digest = decode_lake_snapshot(b'{"id": "a"}\n{"id": "b"}\n', input_format="ndjson")
    assert [r["id"] for r in rows] == ["a", "b"] and len(digest) == 64
    with pytest.raises(ValueError):
        decode_lake_snapshot(b"{}\n" * 1001, input_format="ndjson")
    with pytest.raises(ValueError):
        decode_lake_snapshot(b"{}\nnot-json\n", input_format="ndjson")


def test_local_read_and_unsupported_network_source(tmp_path):
    path = tmp_path / "input.json"
    path.write_text(json.dumps([{"id": "a"}]))
    data, receipt = read_lake_snapshot(str(path))
    assert json.loads(data) == [{"id": "a"}]
    assert receipt == {"kind": "local_export"}
    with pytest.raises(ValueError):
        read_lake_snapshot("https://example.com/data.json")


def test_short_s3_object_is_rejected(monkeypatch):
    stream = io.BytesIO(b"[]")
    client = SimpleNamespace(get_object=lambda **kw: {"Body": stream, "VersionId": "v1", "ContentLength": 3}, close=lambda: None)
    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace(client=lambda *a, **kw: client))
    monkeypatch.setitem(sys.modules, "botocore.config", SimpleNamespace(Config=lambda **kw: kw))
    with pytest.raises(ValueError, match="Incomplete"):
        read_lake_snapshot("s3://sample-lake/findings.json", version_id="v1", expected_owner="123456789012")
    assert stream.closed


def test_credential_provider_error_is_sanitized(monkeypatch):
    def denied(*args, **kwargs):
        raise RuntimeError("private credential context")

    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace(client=denied))
    monkeypatch.setitem(sys.modules, "botocore.config", SimpleNamespace(Config=lambda **kw: kw))
    with pytest.raises(ValueError, match="Cannot read the pinned lake object") as raised:
        read_lake_snapshot("s3://sample-lake/findings.json", version_id="v1", expected_owner="123456789012")
    assert "private" not in str(raised.value)
