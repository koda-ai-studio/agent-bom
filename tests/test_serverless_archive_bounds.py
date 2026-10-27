"""Untrusted deployment ZIPs must be bounded and incomplete on rejection."""

import io
import zipfile
from contextlib import contextmanager

import httpx
import pytest

from agent_bom.cloud.serverless_zip import packages_from_zip_bytes


def _zip(entries, compression=zipfile.ZIP_STORED):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=compression) as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return out.getvalue()


def test_zip_expansion_is_rejected_not_clean():
    data = _zip([("pkg.dist-info/METADATA", b"x" * 200_000)], zipfile.ZIP_DEFLATED)
    with pytest.raises(ValueError, match="ratio"):
        packages_from_zip_bytes(data, ecosystem="pypi")


def test_malformed_zip_is_not_clean():
    with pytest.raises(ValueError, match="archive"):
        packages_from_zip_bytes(b"not a zip", ecosystem="pypi")


def test_zip_member_count_is_bounded():
    data = _zip([(f"f{i}", b"") for i in range(10_001)])
    with pytest.raises(ValueError, match="member"):
        packages_from_zip_bytes(data, ecosystem="pypi")


def test_oversized_metadata_member_is_rejected():
    data = _zip([("pkg.dist-info/METADATA", b"x" * (8 * 1024 * 1024 + 1))])
    with pytest.raises(ValueError, match="member"):
        packages_from_zip_bytes(data, ecosystem="pypi")


def test_http_download_stops_stream_at_budget(monkeypatch):
    from agent_bom import http_client

    read = []

    class Stream(httpx.SyncByteStream):
        def __iter__(self):
            for i in range(100):
                read.append(i)
                yield b"x" * 1024

    @contextmanager
    def client(**kwargs):
        with httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, stream=Stream()))) as c:
            yield c

    monkeypatch.setattr(http_client, "create_sync_client", client)
    with pytest.raises(ValueError, match="byte limit"):
        http_client.fetch_bytes("https://example.test/archive", max_bytes=2048)
    assert len(read) <= 3


def test_total_uncompressed_budget_checked_before_member_reads(monkeypatch):
    from agent_bom.cloud import archive_limits

    data = _zip([("a", b"1234"), ("b", b"1234")])
    monkeypatch.setattr(archive_limits, "MAX_TOTAL_BYTES", 7)
    with pytest.raises(ValueError, match="total uncompressed"):
        packages_from_zip_bytes(data, ecosystem="pypi")


def test_sdk_download_sink_does_not_retain_over_budget_bytes(monkeypatch):
    from agent_bom.cloud import archive_limits

    monkeypatch.setattr(archive_limits, "MAX_ARCHIVE_BYTES", 3)
    with archive_limits.BoundedArchiveBuffer() as sink:
        sink.write(b"ab")
        with pytest.raises(ValueError, match="compressed byte"):
            sink.write(b"cd")
        assert sink.getvalue() == b"ab"


@pytest.mark.parametrize("provider", ["lambda", "azure", "gcp"])
def test_provider_rejection_is_incomplete(monkeypatch, provider):
    import sys
    import types
    from types import SimpleNamespace

    from agent_bom import http_client
    from agent_bom.cloud import serverless_zip
    from agent_bom.cloud.archive_limits import MAX_ARCHIVE_BYTES
    from agent_bom.cloud.aws_lambda_packages import _extract_lambda_packages

    limits = []

    def fetch(url, **kwargs):
        limits.append(kwargs["max_bytes"])
        return b"invalid archive"

    monkeypatch.setattr(http_client, "fetch_bytes", fetch)
    warnings = []
    if provider == "lambda":
        client = SimpleNamespace(
            get_function=lambda **kw: {
                "Configuration": {"Runtime": "python3.12", "Layers": [{"Arn": "layer"}]},
                "Code": {"Location": "https://example.test/code"},
            },
            get_layer_version_by_arn=lambda **kw: {"Content": {"Location": "https://example.test/layer"}},
        )
        packages = _extract_lambda_packages(SimpleNamespace(client=lambda *a, **kw: client), "function", "region", warnings)
        assert limits == [MAX_ARCHIVE_BYTES, MAX_ARCHIVE_BYTES]
        assert len(warnings) == 2
    elif provider == "azure":
        client = SimpleNamespace(
            web_apps=SimpleNamespace(
                list_publishing_credentials=lambda *a: SimpleNamespace(
                    scm_uri="https://example.test", publishing_user_name="fixture", publishing_password="fixture"
                )
            )
        )
        packages = serverless_zip.extract_azure_function_packages(client, "group", "app", "python", warnings)
        assert limits == [MAX_ARCHIVE_BYTES]
    else:

        def download(sink, **kw):
            assert kw["raw_download"] is True
            assert blob.chunk_size == 256 * 1024
            sink.write(b"invalid archive")

        blob = SimpleNamespace(download_to_file=download)
        storage = types.ModuleType("google.cloud.storage")
        storage.Client = lambda: SimpleNamespace(bucket=lambda name: SimpleNamespace(blob=lambda name: blob))
        google = types.ModuleType("google")
        cloud = types.ModuleType("google.cloud")
        google.cloud = cloud
        cloud.storage = storage
        for name, module in [("google", google), ("google.cloud", cloud), ("google.cloud.storage", storage)]:
            monkeypatch.setitem(sys.modules, name, module)
        packages = serverless_zip.extract_gcp_storage_source_packages("bucket", "object", "python", warnings)
    assert packages == []
    assert warnings and all("coverage incomplete" in item for item in warnings)


def test_node_zip_valid_metadata_and_malformed_member():
    data = _zip([("node_modules/pkg/package.json", b'{"name":"pkg","version":"1.2.3"}')])
    assert [(p.name, p.version) for p in packages_from_zip_bytes(data, ecosystem="npm")] == [("pkg", "1.2.3")]
    bad = _zip([("node_modules/pkg/package.json", b"{bad")])
    with pytest.raises(ValueError, match="metadata"):
        packages_from_zip_bytes(bad, ecosystem="npm")


@pytest.mark.parametrize("headers", [{"content-length": "5000"}, {"content-encoding": "gzip"}])
def test_http_refuses_oversized_or_encoded_response_before_body(monkeypatch, headers):
    from agent_bom import http_client

    read = []

    class Stream(httpx.SyncByteStream):
        def __iter__(self):
            read.append(True)
            yield b"payload"

    @contextmanager
    def client(**kwargs):
        with httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, headers=headers, stream=Stream()))) as c:
            yield c

    monkeypatch.setattr(http_client, "create_sync_client", client)
    with pytest.raises(ValueError, match="byte limit"):
        http_client.fetch_bytes("https://example.test/archive", max_bytes=100)
    assert read == []


def test_http_valid_archive_at_exact_budget(monkeypatch):
    from agent_bom import http_client

    class Stream(httpx.SyncByteStream):
        def __iter__(self):
            yield b"ab"
            yield b"cd"

    @contextmanager
    def client(**kwargs):
        with httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, stream=Stream()))) as c:
            yield c

    monkeypatch.setattr(http_client, "create_sync_client", client)
    assert http_client.fetch_bytes("https://example.test/archive", max_bytes=4) == b"abcd"
