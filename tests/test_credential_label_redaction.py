"""Credential metadata stays useful while credential values remain redacted."""

from agent_bom.security import sanitize_sensitive_payload


def test_credential_ranking_preserves_env_name_and_auth_mode():
    payload = {"credential_risk_ranking": [{"credential": "OPENAI_API_KEY"}], "auth_mode": "configured-http-auth"}
    assert sanitize_sensitive_payload(payload) == payload


def test_credential_field_still_redacts_values():
    for value in ("ordinary-password", "ghp_" + "X" * 36, "sk-" + "Y" * 24):
        assert sanitize_sensitive_payload({"credential": value}) == {"credential": "***REDACTED***"}
