"""Credential bindings require the server secret, nonce and credential domain."""

import hashlib
import hmac
import json
import secrets

import pytest

from agent_bom.api import browser_session as sessions


@pytest.fixture
def binding_context(monkeypatch):
    signing_key = secrets.token_bytes(32)
    credential = "synthetic-" + "binding-credential"
    monkeypatch.setattr(sessions, "_signing_key", lambda: signing_key)
    monkeypatch.setenv("AGENT_BOM_API_KEY", credential)
    monkeypatch.delenv("AGENT_BOM_API_KEY_FILE", raising=False)
    monkeypatch.setenv("AGENT_BOM_CONTROL_PLANE_REPLICAS", "1")
    return signing_key, credential


@pytest.mark.parametrize("bind", [sessions._static_key_binding, sessions._operator_key_binding])
@pytest.mark.parametrize("changed", ["signing_key", "nonce", "credential"])
def test_binding_depends_on_each_security_input(binding_context, bind, changed):
    signing_key, credential = binding_context
    original = bind(signing_key, "session-one", credential)
    other = bind(
        secrets.token_bytes(32) if changed == "signing_key" else signing_key,
        "session-two" if changed == "nonce" else "session-one",
        credential + "-rotated" if changed == "credential" else credential,
    )
    assert not hmac.compare_digest(original, other)


def test_static_and_operator_bindings_are_not_interchangeable(binding_context):
    signing_key, credential = binding_context
    static = sessions._static_key_binding(signing_key, "same-nonce", credential)
    operator = sessions._operator_key_binding(signing_key, "same-nonce", credential)
    assert not hmac.compare_digest(static, operator)


def _substitute_binding(kind, signing_key, nonce, credential, *, operator=False):
    bind = sessions._operator_key_binding if operator else sessions._static_key_binding
    if kind == "unkeyed_hash":
        domain = "operator" if operator else "static"
        return hashlib.sha256(f"agent-bom-{domain}-session:v1:{nonce}:{credential}".encode()).hexdigest()
    if kind == "other_signing_key":
        return bind(secrets.token_bytes(32), nonce, credential)
    if kind == "other_nonce":
        return bind(signing_key, nonce + "-other", credential)
    other_domain = sessions._static_key_binding if operator else sessions._operator_key_binding
    return other_domain(signing_key, nonce, credential)


@pytest.mark.parametrize("substitution", ["unkeyed_hash", "other_signing_key", "other_nonce", "other_domain"])
def test_static_binding_rejects_substitution_even_in_signed_envelope(binding_context, substitution):
    signing_key, credential = binding_context
    token, _ = sessions.create_browser_session_token(
        subject="static-key",
        role="admin",
        tenant_id="default",
        auth_method="browser_session_static_api_key",
        static_api_key=credential,
        max_age_seconds=60,
    )
    payload = sessions.verify_browser_session_token(token)
    payload["static_key_binding"] = _substitute_binding(substitution, signing_key, payload["nonce"], credential)
    encoded = sessions._b64encode(json.dumps(payload).encode())
    # Sign deliberately to isolate binding verification from envelope checking.
    # This fixture does not model an attacker who holds the server signing key.
    signature = hmac.digest(signing_key, encoded.encode(), "sha256")
    substituted = f"{encoded}.{sessions._b64encode(signature)}"
    with pytest.raises(sessions.BrowserSessionError, match="backing key is no longer active"):
        sessions.verify_browser_session_token(substituted)


@pytest.mark.parametrize("substitution", ["unkeyed_hash", "other_signing_key", "other_nonce", "other_domain"])
def test_operator_binding_rejects_substitution(binding_context, substitution):
    signing_key, credential = binding_context
    nonce = "operator-session"
    binding = sessions._operator_key_binding(signing_key, nonce, credential)
    assert sessions.verify_operator_session_binding(binding, nonce, credential)
    substituted = _substitute_binding(substitution, signing_key, nonce, credential, operator=True)
    assert not sessions.verify_operator_session_binding(substituted, nonce, credential)
