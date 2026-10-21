"""A responding demo is not proof of private, tenant-scoped vendor evidence."""

import copy
import importlib.util

import pytest

SPEC = importlib.util.spec_from_file_location("vendor_smoke", "scripts/deploy/vendor_qualification_smoke.py")
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


def fixture_reader(overrides=None):
    health = {"version": "test", "auth_required": True, "auth_configured": True, "unauthenticated_allowed": False}
    graph = {
        "tenant_id": "primary",
        "scan_id": "live-1",
        "snapshot_generation": "generation-1",
        "nodes": [{"id": "scoped-resource", "attributes": {"cloud_provider": "gcp"}}],
        "edges": [],
        "pagination": {"has_more": False, "total": 1},
        "completeness": {"truncated": False, "edges_truncated": False},
    }
    calls = []

    def read(path, key=None, headers=None):
        calls.append((path, key, headers))
        if overrides and (path, key) in overrides:
            return copy.deepcopy(overrides[path, key])
        if path == "/health":
            return 200, copy.deepcopy(health)
        if key not in {"primary-key", "other-key"}:
            return 401, {}
        tenant = "primary" if key == "primary-key" else "other"
        if path == "/v1/auth/me":
            return 200, {"authenticated": True, "tenant_id": tenant}
        if path == "/v1/system/health":
            return 200, {"storage": {k: "postgres" for k in ("control_plane_backend", "graph_store", "job_store", "key_store")}}
        if path == "/v1/graph?limit=5000":
            result = copy.deepcopy(graph)
            if tenant == "other":
                result.update(tenant_id="other", nodes=[], edges=[], pagination={"has_more": False, "total": 0})
            return 200, result
        return 200, {}

    return read, calls


def run(read):
    return smoke.qualify(
        read, version="test", tenant="primary", other_tenant="other", key="primary-key", other_key="other-key", providers={"gcp"}
    )


def test_probe_checks_anonymous_invalid_auth_isolation_and_scoped_evidence():
    read, calls = fixture_reader()
    receipt = run(read)
    assert receipt["status"] == "passed" and receipt["nodes"] == 1
    assert receipt["providers"] == ["gcp"] and receipt["restart_performed_by_probe"] is False
    assert any(headers for _, _, headers in calls)
    assert "primary-key" not in str(receipt)


@pytest.mark.parametrize(
    "path,key,body",
    [
        ("/v1/graph?limit=5000", None, {}),
        ("/v1/graph?limit=5000", "invalid-qualification-key", {}),
        ("/v1/system/health", None, {}),
        ("/health", None, {"version": "old", "auth_required": True, "auth_configured": True, "unauthenticated_allowed": False}),
        ("/v1/auth/me", "primary-key", {"authenticated": True, "tenant_id": "other"}),
        ("/v1/system/health", "primary-key", {"storage": {"graph_store": "inmemory"}}),
    ],
)
def test_probe_fails_closed_on_wrong_auth_version_or_storage(path, key, body):
    read, _ = fixture_reader({(path, key): (200, body)})
    with pytest.raises(smoke.QualificationError):
        run(read)


@pytest.mark.parametrize(
    "change",
    [
        {"nodes": []},
        {"tenant_id": "other"},
        {"scan_id": "showcase"},
        {"pagination": {"has_more": True}},
        {"completeness": {"truncated": True}},
        {"nodes": [{"id": "x", "attributes": {"cloud_provider": "aws"}}]},
    ],
)
def test_probe_rejects_missing_wrong_or_bounded_graph(change):
    read, _ = fixture_reader()
    _, graph = read("/v1/graph?limit=5000", "primary-key")
    graph.update(change)
    bad, _ = fixture_reader({("/v1/graph?limit=5000", "primary-key"): (200, graph)})
    with pytest.raises(smoke.QualificationError):
        run(bad)


def test_probe_rejects_cross_tenant_leak():
    read, _ = fixture_reader()
    _, graph = read("/v1/graph?limit=5000", "primary-key")
    graph["tenant_id"] = "other"
    bad, _ = fixture_reader({("/v1/graph?limit=5000", "other-key"): (200, graph)})
    with pytest.raises(smoke.QualificationError):
        run(bad)


def test_key_file_is_private_and_receipt_cannot_overwrite_it(tmp_path):
    key = tmp_path / "key"
    key.write_text("private-key")
    key.chmod(0o644)
    with pytest.raises(smoke.QualificationError):
        smoke.read_key(key)
    key.chmod(0o600)
    assert smoke.read_key(key) == "private-key"
    with pytest.raises(smoke.QualificationError):
        smoke.check_paths(key, tmp_path / "other", key, None)


@pytest.mark.parametrize(
    "url", ["http://example.test", "https://user:secret@example.test", "https://example.test/?key=secret", "https://example.test/#secret"]
)
def test_remote_plaintext_or_credential_urls_are_rejected(url):
    with pytest.raises(smoke.QualificationError):
        smoke.HttpReader(url)


def test_baseline_requires_same_origin_tenant_and_exact_evidence():
    read, _ = fixture_reader()
    current = run(read)
    current["url"] = "https://example.test"
    smoke.compare_baseline(current, copy.deepcopy(current))
    for field in ("tenant", "graph_sha256", "url", "version"):
        previous = dict(current, **{field: "different"})
        with pytest.raises(smoke.QualificationError):
            smoke.compare_baseline(current, previous)


def test_real_http_cli_writes_private_receipt_without_credentials(tmp_path):
    import json
    import subprocess
    import sys
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    read, _ = fixture_reader()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            key = self.headers.get("Authorization", "").removeprefix("Bearer ") or None
            status, body = read(self.path, key, dict(self.headers))
            self.send_response(status)
            self.end_headers()
            self.wfile.write(json.dumps(body).encode())

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        key, other, output = (tmp_path / name for name in ("key", "other", "receipt.json"))
        for path, value in ((key, "primary-key"), (other, "other-key")):
            path.write_text(value)
            path.chmod(0o600)
        result = subprocess.run(
            [
                sys.executable,
                "scripts/deploy/vendor_qualification_smoke.py",
                "--url",
                f"http://127.0.0.1:{server.server_port}",
                "--version",
                "test",
                "--tenant",
                "primary",
                "--other-tenant",
                "other",
                "--provider",
                "gcp",
                "--api-key-file",
                str(key),
                "--other-tenant-key-file",
                str(other),
                "--output",
                str(output),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, result.stdout
        assert json.loads(output.read_text())["status"] == "passed"
        assert output.stat().st_mode & 0o077 == 0
        assert "primary-key" not in result.stdout + result.stderr + output.read_text()
    finally:
        server.shutdown()
        worker.join()
        server.server_close()


@pytest.mark.parametrize("mode", ["redirect", "large", "invalid"])
def test_http_reader_rejects_redirects_and_unbounded_or_invalid_bodies(mode):
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    paths = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            paths.append(self.path)
            self.send_response(302 if mode == "redirect" else 200)
            if mode == "redirect":
                self.send_header("Location", "/secret-destination")
            self.end_headers()
            try:
                self.wfile.write(b"x" * (smoke.MAX_BYTES + 1) if mode == "large" else b"invalid")
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        reader = smoke.HttpReader(f"http://127.0.0.1:{server.server_port}")
        with pytest.raises(smoke.QualificationError):
            reader("/health", "private-key")
        assert paths == ["/health"]
    finally:
        server.shutdown()
        worker.join()
        server.server_close()
