#!/usr/bin/env python3
"""Read-only qualification gate for a bounded, authenticated vendor demo."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

MAX_BYTES = 2 * 1024 * 1024
GRAPH = "/v1/graph?limit=5000"


class QualificationError(ValueError):
    """A fixed diagnostic that contains no response data or credentials."""


def require(condition, message):
    if not condition:
        raise QualificationError(message)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise QualificationError("redirect_rejected")


class HttpReader:
    def __init__(self, url):
        parsed = urlsplit(url)
        local = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        require(parsed.scheme == "https" or (parsed.scheme == "http" and local), "https_required")
        require(bool(parsed.hostname) and not parsed.username and not parsed.password, "invalid_origin")
        require(not parsed.query and not parsed.fragment and parsed.path in {"", "/"}, "origin_only_required")
        self.url = url.rstrip("/")
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def __call__(self, path, key=None, headers=None):
        request_headers = {"Accept": "application/json", **(headers or {})}
        if key:
            request_headers["Authorization"] = "Bearer " + key
        request = urllib.request.Request(self.url + path, headers=request_headers, method="GET")
        try:
            response = self.opener.open(request, timeout=30)
        except urllib.error.HTTPError as exc:
            # Error bodies can contain private evidence; status alone is sufficient.
            status = exc.code
            exc.close()
            return status, {}
        except (OSError, ValueError) as exc:
            raise QualificationError("request_failed") from exc
        with response:
            raw = response.read(MAX_BYTES + 1)
            require(len(raw) <= MAX_BYTES, "response_too_large")
            try:
                data = json.loads(raw)
            except (ValueError, UnicodeError) as exc:
                raise QualificationError("invalid_json") from exc
            require(isinstance(data, dict), "invalid_response_shape")
            return response.status, data


def read_key(path):
    require(path.is_file() and path.stat().st_size <= 4096, "invalid_key_file")
    require(os.name == "nt" or not path.stat().st_mode & 0o077, "key_file_must_be_private")
    key = path.read_text().strip()
    require(bool(key) and all(32 < ord(char) < 127 for char in key), "invalid_key")
    return key


def check_paths(key, other_key, output, baseline):
    paths = [key, other_key, output] + ([baseline] if baseline else [])
    require(len({p.resolve() for p in paths}) == len(paths), "paths_must_differ")


def _get(read, path, key):
    status, body = read(path, key)
    require(status == 200 and isinstance(body, dict), "authenticated_read_failed")
    return body


def _graph(body, tenant):
    require(body.get("tenant_id") == tenant, "graph_tenant_mismatch")
    require(isinstance(body.get("scan_id"), str) and bool(body["scan_id"]), "snapshot_required")
    require("showcase" not in body["scan_id"].lower(), "synthetic_showcase_rejected")
    require(isinstance(body.get("nodes"), list) and isinstance(body.get("edges"), list), "invalid_graph")
    require(body.get("pagination", {}).get("has_more") is False, "graph_page_incomplete")
    completeness = body.get("completeness", {})
    require(completeness.get("truncated") is False and completeness.get("edges_truncated") is False, "graph_bounded")
    ids = [node.get("id") for node in body["nodes"] if isinstance(node, dict)]
    require(len(ids) == len(body["nodes"]) and all(isinstance(i, str) and i for i in ids), "invalid_node_ids")
    require(len(ids) == len(set(ids)), "duplicate_node_ids")
    return body


def _digest(graph):
    evidence = {name: sorted(graph[name], key=lambda row: json.dumps(row, sort_keys=True)) for name in ("nodes", "edges")}
    return hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def qualify(read, *, version, tenant, other_tenant, key, other_key, providers):
    require(tenant != other_tenant and key != other_key and bool(providers), "distinct_tenants_and_keys_required")
    health = _get(read, "/health", None)
    require(health.get("version") == version, "version_mismatch")
    require(health.get("auth_required") is True and health.get("auth_configured") is True, "auth_not_required")
    require(health.get("unauthenticated_allowed") is False, "anonymous_mode_enabled")
    for path, credential in ((GRAPH, None), (GRAPH, "invalid-qualification-key"), ("/v1/system/health", None)):
        status, _ = read(path, credential)
        require(status in {401, 403}, "unauthenticated_read_not_denied")
    for credential, expected in ((key, tenant), (other_key, other_tenant)):
        identity = _get(read, "/v1/auth/me", credential)
        require(identity.get("authenticated") is True and identity.get("tenant_id") == expected, "identity_mismatch")
    storage = _get(read, "/v1/system/health", key).get("storage", {})
    require(
        all(storage.get(k) == "postgres" for k in ("control_plane_backend", "graph_store", "job_store", "key_store")), "postgres_required"
    )
    graph = _graph(_get(read, GRAPH, key), tenant)
    require(bool(graph["nodes"]), "vendor_evidence_missing")
    found = {str(n.get("attributes", {}).get("cloud_provider") or n.get("attributes", {}).get("provider") or "") for n in graph["nodes"]}
    require(providers <= found, "expected_provider_missing")
    other = _graph(_get(read, GRAPH, other_key), other_tenant)
    require(not other["nodes"] and not other["edges"], "control_tenant_not_empty")
    status, spoofed = read(GRAPH, key, {"X-Agent-Bom-Tenant-ID": other_tenant, "X-Tenant-ID": other_tenant})
    require(status == 200, "tenant_header_probe_failed")
    require(_digest(_graph(spoofed, tenant)) == _digest(graph), "tenant_header_changed_evidence")
    for path in ("/v1/overview", "/v1/findings?limit=1"):
        _get(read, path, key)
    return {
        "schema_version": "vendor.qualification.v1",
        "status": "passed",
        "version": version,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "tenant": tenant,
        "control_tenant": other_tenant,
        "providers": sorted(providers),
        "nodes": len(graph["nodes"]),
        "edges": len(graph["edges"]),
        "graph_sha256": _digest(graph),
        "restart_performed_by_probe": False,
        "baseline_match": None,
        "provider_live_collection_verified": False,
        "browser_journey_verified": False,
        "finding_accuracy_verified": False,
    }


def compare_baseline(current, previous):
    require(previous.get("status") == "passed", "baseline_not_passed")
    for field in ("url", "version", "tenant", "control_tenant", "providers", "graph_sha256"):
        require(current.get(field) == previous.get(field), "baseline_mismatch")
    current["baseline_match"] = True


def write_receipt(path, receipt):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(receipt, stream, indent=2)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("url", "version", "tenant", "other-tenant"):
        parser.add_argument("--" + name, required=True)
    for name in ("api-key-file", "other-tenant-key-file", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--provider", action="append", required=True)
    parser.add_argument("--baseline", type=Path)
    args = parser.parse_args()
    try:
        check_paths(args.api_key_file, args.other_tenant_key_file, args.output, args.baseline)
        reader = HttpReader(args.url)
        receipt = qualify(
            reader,
            version=args.version,
            tenant=args.tenant,
            other_tenant=args.other_tenant,
            key=read_key(args.api_key_file),
            other_key=read_key(args.other_tenant_key_file),
            providers=set(args.provider),
        )
        receipt["url"] = reader.url
        if args.baseline:
            compare_baseline(receipt, json.loads(args.baseline.read_text()))
        write_receipt(args.output, receipt)
    except Exception:
        # Never print exception objects, response data, URLs, or credentials.
        print("Vendor qualification failed; verify auth, version, tenant scope, storage and bounded vendor evidence.")
        return 1
    print("Vendor API qualification passed; private receipt written. Browser and provider qualification are separate.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
