"""Session attempt limits, forwarded-address parsing, websocket tokens and the Secret-sourced proxy settings."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from starlette.datastructures import Headers

from agent_bom.api import forwarded_identity
from agent_bom.api.forwarded_identity import resolve_forwarded_client_ip
from tests._helm_render import ATTESTED_API_SET_ARGS

UNPARSEABLE_FORWARDED_SOURCE = getattr(forwarded_identity, "UNPARSEABLE_FORWARDED_SOURCE", "unparseable-forwarded-address")

_REPO = Path(__file__).resolve().parents[1]


def _request(peer, lines):
    return SimpleNamespace(
        client=SimpleNamespace(host=peer),
        headers=Headers(raw=[(b"x-forwarded-for", line.encode()) for line in lines]),
        state=SimpleNamespace(),
    )


@pytest.fixture
def trusted_proxy(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_TRUSTED_PROXY_HOPS", "1")
    monkeypatch.setenv("AGENT_BOM_TRUSTED_PROXY_CIDRS", "192.0.2.0/24")


# Session attempt limiter


def test_session_limiter_uses_every_forwarded_line(trusted_proxy):
    from agent_bom.api.routes.enterprise_routes._session_helpers import _client_fingerprint

    assert _client_fingerprint(_request("192.0.2.1", ["198.51.100.9", "203.0.113.7"])) == "203.0.113.7"


def test_session_limiter_ignores_forwarding_without_trust(monkeypatch):
    from agent_bom.api.routes.enterprise_routes._session_helpers import _client_fingerprint

    monkeypatch.delenv("AGENT_BOM_TRUSTED_PROXY_HOPS", raising=False)
    assert _client_fingerprint(_request("192.0.2.1", ["203.0.113.7"])) == "192.0.2.1"


def test_session_limiter_groups_ipv6_like_the_failure_limit(trusted_proxy):
    from agent_bom.api.routes.enterprise_routes._session_helpers import _client_fingerprint

    first = _client_fingerprint(_request("192.0.2.1", ["2001:db8:1:2::1"]))
    assert first == _client_fingerprint(_request("192.0.2.1", ["2001:db8:1:2::ff"]))


def test_a_blank_key_does_not_spend_the_session_attempt_budget(monkeypatch):
    from fastapi import FastAPI
    from starlette.testclient import TestClient

    from agent_bom.api import auth
    from agent_bom.api.auth import KeyStore
    from agent_bom.api.routes.enterprise_routes.keys import router
    from agent_bom.api.shared_auth_state import reset_auth_state_for_tests

    monkeypatch.setenv("AGENT_BOM_AUTH_SESSION_ATTEMPTS_PER_MINUTE", "3")
    monkeypatch.setattr(auth, "_key_store", KeyStore())
    reset_auth_state_for_tests()
    app = FastAPI()
    app.include_router(router, prefix="/v1")
    with TestClient(app, client=("192.0.2.90", 1000)) as client:
        assert {client.post("/v1/auth/session", json={"api_key": "   "}).status_code for _ in range(10)} == {401}
        assert client.post("/v1/auth/session", json={"api_key": "wrong-but-real-attempt"}).status_code == 401


def test_no_identity_or_limit_reads_one_forwarded_line_outside_the_shared_resolver():
    # The public MCP tier reads every line itself under its own documented hop setting.
    allowed = {"src/agent_bom/api/forwarded_identity.py", "src/agent_bom/mcp_tools/public_tier.py"}
    offenders = []
    for path in (_REPO / "src/agent_bom").rglob("*.py"):
        relative = path.relative_to(_REPO).as_posix()
        if relative in allowed:
            continue
        if re.search(r"""["']x-forwarded-for["']""", path.read_text(errors="replace"), re.IGNORECASE):
            offenders.append(relative)
    assert offenders == []


# Forwarded entries a proxy writes with a port, or not as an address at all


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        ("203.0.113.7:51234", "203.0.113.7"),
        ("[2001:db8::7]:443", "2001:db8::7"),
        ("[2001:db8::7]", "2001:db8::7"),
        ('"203.0.113.7"', "203.0.113.7"),
        ("2001:db8::7", "2001:db8::7"),
    ],
)
def test_proxy_written_ports_and_brackets_are_parsed(trusted_proxy, entry, expected):
    assert resolve_forwarded_client_ip(peer_host="192.0.2.1", forwarded_for=entry) == expected


@pytest.mark.parametrize("entry", ["unknown", "_hidden", "203.0.113.7:notaport", "not-an-address"])
def test_an_unparseable_entry_never_lands_on_the_proxys_budget(trusted_proxy, entry):
    from agent_bom.api.auth_failure_policy import AuthFailurePolicy

    policy = AuthFailurePolicy()
    assert policy.source(_request("192.0.2.1", [entry])) == UNPARSEABLE_FORWARDED_SOURCE
    # Other consumers keep their previous fallback.
    assert resolve_forwarded_client_ip(peer_host="192.0.2.1", forwarded_for=entry) == "192.0.2.1"


def test_unparseable_entries_warn_once_without_contents(trusted_proxy, caplog):
    from agent_bom.api.auth_failure_policy import AuthFailurePolicy

    policy = AuthFailurePolicy()
    for _ in range(3):
        policy.source(_request("192.0.2.1", ["caller-written-value"]))
    assert sum("could not be read as an address" in record.getMessage() for record in caplog.records) == 1
    assert "caller-written-value" not in caplog.text


@pytest.mark.asyncio
async def test_failures_from_an_unparseable_entry_do_not_block_clients_with_addresses(trusted_proxy, monkeypatch):
    from starlette.responses import JSONResponse

    from agent_bom.api import audit_log
    from agent_bom.api.auth_failure_policy import AuthFailurePolicy

    monkeypatch.setenv("AGENT_BOM_AUTH_FAILURE_LIMIT", "2")
    monkeypatch.setattr(audit_log, "log_action", lambda *_a, **_k: None)
    policy = AuthFailurePolicy()
    for _ in range(3):
        request = _request("192.0.2.1", ["garbage"])
        request.state.authentication_failed = True
        await policy.after(request, JSONResponse({}, status_code=401))
    assert (await policy.before(_request("192.0.2.1", ["garbage"]))).status_code == 429
    assert await policy.before(_request("192.0.2.1", ["203.0.113.8"])) is None
    assert await policy.before(_request("192.0.2.1", [])) is None


# Websocket tokens


def test_non_ascii_websocket_token_is_a_counted_failure(monkeypatch):
    from agent_bom.api import auth
    from agent_bom.api.auth import KeyStore
    from agent_bom.api.websocket_auth import _ws_auth_from_token

    monkeypatch.setenv("AGENT_BOM_API_KEY", "static-websocket-key")
    monkeypatch.setattr(auth, "_key_store", KeyStore())
    rejected: list[bool] = []
    assert _ws_auth_from_token("pässwörd", bearer=False, rejected=rejected) is None
    assert rejected == [True]


# Proxy settings supplied by a Secret


def _helm(*args):
    if shutil.which("helm") is None:
        pytest.skip("helm is not on PATH")
    return subprocess.run(["helm", "template", "release", str(_REPO / "deploy/helm/agent-bom"), *args], capture_output=True, text=True)


_INGRESS = (
    "--set",
    "controlPlane.enabled=true",
    "--set",
    "controlPlane.api.enabled=true",
    "--set",
    "controlPlane.migrations.enabled=false",
    "--set",
    "controlPlane.ingress.enabled=true",
    "--set",
    "controlPlane.api.trustedProxy.fromSecret=true",
    *ATTESTED_API_SET_ARGS,
)


def _api_env(rendered):
    for doc in yaml.safe_load_all(rendered):
        if isinstance(doc, dict) and doc.get("kind") == "Deployment" and doc["metadata"]["name"].endswith("-api"):
            return {entry["name"]: entry for entry in doc["spec"]["template"]["spec"]["containers"][0].get("env", [])}
    raise AssertionError("no API deployment rendered")


def test_secret_sourced_proxy_settings_must_name_their_secret():
    result = _helm(*_INGRESS)
    assert result.returncode != 0
    assert "trustedProxy.secretName" in result.stderr


def test_secret_sourced_proxy_settings_are_required_keys_of_that_secret():
    result = _helm(*_INGRESS, "--set", "controlPlane.api.trustedProxy.secretName=proxy-settings")
    assert result.returncode == 0, result.stderr
    env = _api_env(result.stdout)
    for name in ("AGENT_BOM_TRUSTED_PROXY_HOPS", "AGENT_BOM_TRUSTED_PROXY_CIDRS"):
        reference = env[name]["valueFrom"]["secretKeyRef"]
        assert reference == {"name": "proxy-settings", "key": name}


def test_example_secret_for_eks_vanilla_declares_both_proxy_keys():
    values = yaml.safe_load((_REPO / "deploy/helm/agent-bom/examples/eks-vanilla-values.yaml").read_text())
    trusted = values["controlPlane"]["api"]["trustedProxy"]
    secrets = [
        doc
        for doc in yaml.safe_load_all((_REPO / "deploy/helm/agent-bom/examples/control-plane-auth-secret.example.yaml").read_text())
        if doc
    ]
    named = [doc for doc in secrets if doc["metadata"]["name"] == trusted["secretName"]]
    assert named
    assert any({"AGENT_BOM_TRUSTED_PROXY_HOPS", "AGENT_BOM_TRUSTED_PROXY_CIDRS"} <= set(doc["stringData"]) for doc in named)


def test_docs_list_the_unparseable_forwarded_entry():
    docs = (_REPO / "docs/RUNTIME_FAIL_MODES.md").read_text()
    assert "cannot be read as an address" in docs
