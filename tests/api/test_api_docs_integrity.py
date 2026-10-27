"""Documentation code is pinned, integrity-checked, and authorized by a fresh nonce."""

import re

import pytest
from starlette.testclient import TestClient

from agent_bom.api.server import app


@pytest.mark.parametrize("path", ["/docs", "/redoc"])
def test_documentation_scripts_have_exact_versions_integrity_and_nonce(path):
    with TestClient(app) as client:
        response = client.get(path)
        second = client.get(path)
    assert response.status_code == 200
    tags = re.findall(r"<script\b[^>]*>", response.text)
    assert tags
    nonces = []
    for tag in tags:
        nonce = re.search(r'nonce="([^"]+)"', tag)
        assert nonce, tag
        nonces.append(nonce[1])
        if "src=" in tag:
            assert re.search(r"@\d+\.\d+\.\d+/", tag)
            assert 'integrity="sha384-' in tag and 'crossorigin="anonymous"' in tag
    csp = response.headers["content-security-policy"]
    script = next(part for part in csp.split(";") if part.strip().startswith("script-src "))
    assert "unsafe-inline" not in script and "unsafe-eval" not in script
    assert all(f"'nonce-{nonce}'" in script for nonce in nonces)
    assert nonces[0] not in second.text
    assert "fonts.googleapis.com" not in response.text
    if path == "/docs":
        css = next(tag for tag in re.findall(r"<link\b[^>]*>", response.text) if "stylesheet" in tag)
        assert 'integrity="sha384-' in css and 'crossorigin="anonymous"' in css


def test_api_json_keeps_strict_csp():
    with TestClient(app) as client:
        response = client.get("/health")
    assert response.headers["content-security-policy"] == "default-src 'self'"
