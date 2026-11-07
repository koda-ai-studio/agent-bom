"""The ACS URL takes the SAML HTTP-POST binding, only from the browser that started that login."""

from __future__ import annotations

import base64
import json
import zlib
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from urllib.parse import parse_qs, urlencode, urlsplit
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agent_bom.api.auth import KeyStore, get_key_store, set_key_store
from agent_bom.api.browser_session import CSRF_COOKIE_NAME, SESSION_COOKIE_NAME, open_saml_login, seal_saml_login
from agent_bom.api.middleware import APIKeyMiddleware, MaxBodySizeMiddleware
from agent_bom.api.route_policy import public_operation
from agent_bom.api.routes import enterprise
from agent_bom.api.routes.enterprise_routes.sso import SAML_FORM_MAX_BYTES, SAML_LOGIN_COOKIE, SAML_LOGIN_COOKIE_LOCAL
from agent_bom.api.saml import SAMLError
from agent_bom.api.server import app as real_app
from agent_bom.api.shared_auth_state import reset_auth_state_for_tests

ACS = "/v1/auth/saml/login"
START = "/v1/auth/saml/start"
FORM = {"content-type": "application/x-www-form-urlencoded"}
IDP_ORIGIN = {"origin": "https://idp.example.test", "sec-fetch-site": "cross-site"}
SAML_ENV = {
    "AGENT_BOM_SAML_IDP_ENTITY_ID": "https://idp.example.test/metadata",
    "AGENT_BOM_SAML_IDP_SSO_URL": "https://idp.example.test/sso",
    "AGENT_BOM_SAML_IDP_X509_CERT": "MIIC-test-cert",
    "AGENT_BOM_SAML_SP_ENTITY_ID": "https://agent-bom.example.test/sp",
    "AGENT_BOM_SAML_SP_ACS_URL": "https://agent-bom.example.test/v1/auth/saml/login",
}


@pytest.fixture
def store():
    original = get_key_store()
    keys = KeyStore()
    set_key_store(keys)
    reset_auth_state_for_tests()
    try:
        yield keys
    finally:
        set_key_store(original)
        reset_auth_state_for_tests()


def _app() -> FastAPI:
    app = FastAPI()
    app.include_router(enterprise.router, prefix="/v1")
    app.add_middleware(APIKeyMiddleware, api_key="")
    app.add_middleware(MaxBodySizeMiddleware)
    return app


@pytest.fixture
def client(store, monkeypatch: pytest.MonkeyPatch):
    for name, value in SAML_ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY", "synthetic-" + "saml-binding-signing-key")
    monkeypatch.setenv("AGENT_BOM_AUTH_SESSION_ATTEMPTS_PER_MINUTE", "1000")
    monkeypatch.delenv("AGENT_BOM_SAML_ALLOW_IDP_INITIATED", raising=False)
    monkeypatch.setattr("agent_bom.api.saml.saml_runtime_available", lambda: True)
    with TestClient(_app(), base_url="https://agent-bom.example.test", follow_redirects=False) as test_client:
        yield test_client


@pytest.fixture
def verified(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str | None, str | None]]:
    """Stand in for the IdP round trip and record what reached the verifier."""
    calls: list[tuple[str, str | None, str | None]] = []

    def begin(_self, relay_state: str) -> tuple[str, str]:
        return f"https://idp.example.test/sso?{urlencode({'RelayState': relay_state})}", f"ONELOGIN_{uuid4().hex}"

    def verify(_self, saml_response: str, relay_state: str | None = None, request_id: str | None = None) -> SimpleNamespace:
        calls.append((saml_response, relay_state, request_id))
        return SimpleNamespace(
            subject="alice@example.com",
            attributes={"agent_bom_role": "analyst", "tenant_id": "tenant-alpha"},
            role="analyst",
            tenant_id="tenant-alpha",
            session_index="session-1",
        )

    monkeypatch.setattr("agent_bom.api.saml.SAMLConfig.begin_login", begin)
    monkeypatch.setattr("agent_bom.api.saml.SAMLConfig.verify_response", verify)
    return calls


def _start(client: TestClient) -> tuple[str, str]:
    """Begin a login the way a browser does; returns its RelayState and request id."""
    response = client.get(START)
    assert response.status_code == 302, response.text
    relay = parse_qs(urlsplit(response.headers["location"]).query)["RelayState"][0]
    return relay, client.cookies[SAML_LOGIN_COOKIE].split(".")[0]


def _post_form(client: TestClient, **fields: str):
    return client.post(ACS, content=urlencode(fields), headers={**FORM, **IDP_ORIGIN})


def _login_cookie_cleared(response) -> bool:
    return any(c.startswith(f"{SAML_LOGIN_COOKIE}=") and "max-age=0" in c.lower() for c in response.headers.get_list("set-cookie"))


def _no_session(response) -> bool:
    return not any(c.startswith(f"{SESSION_COOKIE_NAME}=") for c in response.headers.get_list("set-cookie"))


# ── Starting a login ─────────────────────────────────────────────────────────


def test_start_is_the_only_new_anonymous_saml_operation() -> None:
    assert public_operation("GET", START)
    assert not public_operation("POST", START)


def test_start_sets_a_host_only_cross_site_cookie_bound_to_the_login(client: TestClient, verified: list) -> None:
    response = client.get(START)

    assert response.status_code == 302
    assert response.headers["cache-control"] == "no-cache, no-store"
    assert response.headers["location"].startswith("https://idp.example.test/sso?")
    cookie = next(c for c in response.headers.get_list("set-cookie") if c.startswith(f"{SAML_LOGIN_COOKIE}="))
    attributes = {part.strip().lower() for part in cookie.split(";")[1:]}
    assert SAML_LOGIN_COOKIE.startswith("__Host-")
    assert {"httponly", "secure", "samesite=none", "path=/", "max-age=300"} <= attributes
    assert not any(attribute.startswith("domain") for attribute in attributes)
    relay = parse_qs(urlsplit(response.headers["location"]).query)["RelayState"][0]
    assert relay not in cookie, "the cookie carries a keyed digest of the relay state, not the value"


def test_start_needs_the_saml_extra_and_shares_the_attempt_limit(client: TestClient, verified: list, monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_AUTH_SESSION_ATTEMPTS_PER_MINUTE", "1")
    assert client.get(START).status_code == 302
    assert client.get(START).status_code == 429

    monkeypatch.setenv("AGENT_BOM_AUTH_SESSION_ATTEMPTS_PER_MINUTE", "1000")
    monkeypatch.setattr("agent_bom.api.saml.saml_runtime_available", lambda: False)
    response = client.get(START)
    assert response.status_code == 503
    assert "[saml] extra" in response.json()["detail"]


def test_plain_http_is_local_only_and_uses_a_separate_cookie(store, verified: list, monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in SAML_ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("AGENT_BOM_SAML_SP_ACS_URL", "http://localhost:8422/v1/auth/saml/login")
    monkeypatch.setenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY", "synthetic-" + "saml-binding-signing-key")
    monkeypatch.setattr("agent_bom.api.saml.saml_runtime_available", lambda: True)
    with TestClient(_app(), base_url="http://localhost:8422", follow_redirects=False) as local:
        response = local.get(START)
        cookie = next(c for c in response.headers.get_list("set-cookie") if c.startswith(f"{SAML_LOGIN_COOKIE_LOCAL}="))
        assert "samesite=lax" in cookie.lower() and "secure" not in cookie.lower()
        relay = parse_qs(urlsplit(response.headers["location"]).query)["RelayState"][0]
        assert _post_form(local, SAMLResponse="assertion", RelayState=relay).status_code == 303

        monkeypatch.setattr("agent_bom.api.middleware._production_or_clustered_control_plane", lambda: True)
        assert local.get(START).status_code == 503, "production never downgrades the login cookie"


def test_https_ignores_the_local_cookie(client: TestClient, verified: list) -> None:
    relay, _request_id = _start(client)
    value = client.cookies[SAML_LOGIN_COOKIE]
    client.cookies.clear()
    client.cookies.set(SAML_LOGIN_COOKIE_LOCAL, value)

    assert _post_form(client, SAMLResponse="assertion", RelayState=relay).status_code == 401
    assert verified == []


# ── Binding, with a stubbed verifier ─────────────────────────────────────────


def test_bound_form_post_starts_a_browser_session(client: TestClient, verified: list, store: KeyStore) -> None:
    relay, request_id = _start(client)
    # A base64 "+" must survive urlencoding exactly as a browser form sends it.
    response = _post_form(client, SAMLResponse="abc+def/==", RelayState=relay)

    assert response.status_code == 303, response.text
    assert response.headers["location"] == "/"
    assert response.headers["cache-control"] == "no-cache, no-store"
    assert verified == [("abc+def/==", relay, request_id)]
    assert "abom_" not in response.text, "the session key must not be rendered into the browser"
    assert _login_cookie_cleared(response)
    cookies = response.headers.get_list("set-cookie")
    session_cookie = next(cookie for cookie in cookies if cookie.startswith(f"{SESSION_COOKIE_NAME}="))
    assert "HttpOnly" in session_cookie and "Secure" in session_cookie and "samesite=strict" in session_cookie.lower()
    assert any(cookie.startswith(f"{CSRF_COOKIE_NAME}=") for cookie in cookies)

    keys = store.list_keys("tenant-alpha")
    assert [key.name for key in keys] == ["saml:alice@example.com"]
    assert keys[0].expires_at

    me = client.get("/v1/auth/me")
    assert me.status_code == 200, me.text
    assert (me.json()["role"], me.json()["tenant_id"], me.json()["auth_method"]) == ("analyst", "tenant-alpha", "saml")


def test_form_session_ends_when_its_short_lived_key_is_gone(client: TestClient, verified: list, store: KeyStore) -> None:
    relay, _request_id = _start(client)
    assert _post_form(client, SAMLResponse="assertion", RelayState=relay).status_code == 303
    assert client.get("/v1/auth/me").status_code == 200

    key = store.list_keys("tenant-alpha")[0]
    assert store.remove(key.key_id)

    assert client.get("/v1/auth/me").status_code == 401


def test_invalid_assertion_is_refused_and_clears_the_login(client: TestClient, verified: list, store: KeyStore, monkeypatch) -> None:
    def reject(_self, _saml_response: str, relay_state: str | None = None, request_id: str | None = None):
        raise SAMLError("SAML assertion validation failed: invalid signature")

    monkeypatch.setattr("agent_bom.api.saml.SAMLConfig.verify_response", reject)
    relay, _request_id = _start(client)

    response = _post_form(client, SAMLResponse="forged", RelayState=relay)

    assert response.status_code == 401
    assert "invalid signature" in response.json()["detail"]
    assert _no_session(response)
    assert _login_cookie_cleared(response)
    assert "location" not in response.headers
    assert store.list_keys("tenant-alpha") == []


@pytest.mark.parametrize("hostile", ["https://evil.example/phish", "//evil.example", "/\\evil.example", "javascript:alert(1)", "/settings"])
def test_relay_state_is_never_a_redirect_target_and_a_mismatch_burns_nothing(client: TestClient, verified: list, hostile: str) -> None:
    relay, _request_id = _start(client)

    response = _post_form(client, SAMLResponse="assertion", RelayState=hostile)

    assert response.status_code == 401
    assert "location" not in response.headers
    assert "evil" not in response.text
    assert verified == []

    # The real login is still open: its one-time nonce was not spent by the mismatch.
    assert _post_form(client, SAMLResponse="assertion", RelayState=relay).status_code == 303


def test_form_attempts_share_the_session_rate_limit(client: TestClient, verified: list, monkeypatch: pytest.MonkeyPatch) -> None:
    relay, _request_id = _start(client)
    monkeypatch.setenv("AGENT_BOM_AUTH_SESSION_ATTEMPTS_PER_MINUTE", "1")

    assert _post_form(client, SAMLResponse="first", RelayState=relay).status_code == 429
    assert verified == []


def test_form_binding_still_needs_the_saml_extra(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agent_bom.api.saml.saml_runtime_available", lambda: False)

    response = client.post(ACS, content="SAMLResponse=abc&RelayState=n", headers=FORM)

    assert response.status_code == 503
    assert "[saml] extra" in response.json()["detail"]


# ── Unsolicited posts ────────────────────────────────────────────────────────


@pytest.mark.parametrize("idp_initiated", [False, True])
@pytest.mark.parametrize("fields", [{"SAMLResponse": "assertion"}, {"SAMLResponse": "assertion", "RelayState": "unissued"}])
def test_unsolicited_form_post_is_refused_even_when_json_allows_idp_initiated(
    client: TestClient, verified: list, monkeypatch: pytest.MonkeyPatch, idp_initiated: bool, fields: dict[str, str]
) -> None:
    if idp_initiated:
        monkeypatch.setenv("AGENT_BOM_SAML_ALLOW_IDP_INITIATED", "1")

    response = _post_form(client, **fields)

    assert response.status_code == 401
    assert START in response.json()["detail"]
    assert _no_session(response)
    assert verified == []


def test_relay_from_the_programmatic_endpoint_does_not_open_the_form_binding(client: TestClient, verified: list) -> None:
    relay = client.post("/v1/auth/saml/relay-state").json()["relay_state"]

    assert _post_form(client, SAMLResponse="assertion", RelayState=relay).status_code == 401
    assert verified == []


def test_login_binding_refuses_values_it_did_not_seal(client: TestClient) -> None:
    sealed = seal_saml_login("relay", "ONELOGIN_x")

    assert open_saml_login(sealed, "relay") == "ONELOGIN_x"
    assert open_saml_login(sealed, "other-relay") is None
    assert open_saml_login(sealed, "") is None
    assert open_saml_login(sealed.replace("ONELOGIN_x", "ONELOGIN_y"), "relay") is None
    for value in ("", "no-separator", "ONELOGIN_x.", ".digest", "é.é", "ONELOGIN_x.é"):
        assert open_saml_login(value, "relay") is None


@pytest.mark.parametrize("value", ["no-separator", "ONELOGIN_x.", ".digest", "ONELOGIN_x.bm90LWEtZGlnZXN0"])
def test_malformed_login_cookie_is_refused(client: TestClient, verified: list, value: str) -> None:
    relay, _request_id = _start(client)
    client.cookies.clear()
    client.cookies.set(SAML_LOGIN_COOKIE, value)

    assert _post_form(client, SAMLResponse="assertion", RelayState=relay).status_code == 401
    assert verified == []


# ── Form bounds ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "body",
    [
        "",
        "RelayState=nonce",
        "SAMLResponse=",
        "SAMLResponse=%20%20",
        "SAMLResponse=one&SAMLResponse=two",
        "SAMLResponse=abc&RelayState=one&RelayState=two",
        "SAMLResponse=%ff%fe",
        "SAMLResponse=abc&not-a-pair",
        "&".join(f"field{number}=x" for number in range(64)) + "&SAMLResponse=abc",
    ],
)
def test_malformed_forms_never_reach_the_verifier(client: TestClient, verified: list, body: str) -> None:
    response = client.post(ACS, content=body, headers=FORM)

    assert response.status_code == 422, response.text
    assert verified == []


def test_oversized_form_is_refused_before_parsing(client: TestClient, verified: list) -> None:
    body = b"SAMLResponse=" + b"a" * SAML_FORM_MAX_BYTES

    response = client.post(ACS, content=body, headers=FORM)

    assert response.status_code == 413
    assert verified == []


# ── JSON contract and neighbours ─────────────────────────────────────────────


def test_json_contract_is_unchanged_and_never_touches_the_login_cookie(client: TestClient, verified: list) -> None:
    relay = client.post("/v1/auth/saml/relay-state").json()["relay_state"]

    response = client.post(ACS, json={"saml_response": "assertion", "relay_state": relay})

    assert response.status_code == 201, response.text
    assert response.json()["raw_key"].startswith("abom_")
    assert "set-cookie" not in response.headers
    assert verified == [("assertion", relay, None)]


@pytest.mark.parametrize(
    ("body", "headers"),
    [
        ('{"saml_response": "x", "extra": 1}', {"content-type": "application/json"}),
        ('{"relay_state": "x"}', {"content-type": "application/json"}),
        ("SAMLResponse=abc", {"content-type": "text/plain"}),
        (
            "--b\r\nContent-Disposition: form-data; name=SAMLResponse\r\n\r\nabc\r\n--b--",
            {"content-type": "multipart/form-data; boundary=b"},
        ),
    ],
)
def test_only_json_and_the_post_binding_are_accepted(client: TestClient, verified: list, body: str, headers: dict[str, str]) -> None:
    response = client.post(ACS, content=body, headers=headers)

    assert response.status_code == 422
    assert isinstance(response.json()["detail"], list), "FastAPI's own validation shape is preserved"
    assert verified == []


@pytest.mark.parametrize("headers", [{}, {"content-type": "text/plain"}, {"content-type": "application/json"}])
def test_cross_site_json_cannot_start_a_browser_session(client: TestClient, verified: list, headers: dict[str, str]) -> None:
    """Whatever a cross-site page can send, the JSON path sets no cookie and its key is unreadable to that page."""
    relay = client.post("/v1/auth/saml/relay-state").json()["relay_state"]
    body = json.dumps({"saml_response": "assertion", "relay_state": relay})

    response = client.post(ACS, content=body, headers={**headers, **IDP_ORIGIN})

    assert "set-cookie" not in response.headers
    assert "access-control-allow-origin" not in response.headers


def test_an_existing_session_on_another_route_keeps_its_csrf_checks(client: TestClient, verified: list) -> None:
    relay, _request_id = _start(client)
    assert _post_form(client, SAMLResponse="assertion", RelayState=relay).status_code == 303

    # The IdP's cross-site origin opens the ACS alone: session-authenticated writes stay refused.
    forged = client.post("/v1/auth/keys", content="a=b", headers={**FORM, **IDP_ORIGIN})
    assert forged.status_code == 403
    assert "origin" in forged.json()["detail"]

    # A signed-in browser returning through the IdP is not stopped at the ACS.
    relay, _request_id = _start(client)
    assert _post_form(client, SAMLResponse="again", RelayState=relay).status_code == 303


def test_openapi_documents_the_start_route_and_both_bindings_on_the_real_app() -> None:
    paths = real_app.openapi()["paths"]
    operation = paths[ACS]["post"]

    content = operation["requestBody"]["content"]
    assert content["application/json"]["schema"]["$ref"].endswith("/SAMLLoginRequest")
    assert content["application/x-www-form-urlencoded"]["schema"]["required"] == ["SAMLResponse", "RelayState"]
    assert {"201", "303", "413"} <= set(operation["responses"])
    assert "302" in paths[START]["get"]["responses"]


# ── The real verifier, with real signatures ──────────────────────────────────


def _signing_identity() -> tuple[str, str, str]:
    """A throwaway IdP key and certificate, generated per run."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "idp.example.test")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    der_b64 = base64.b64encode(certificate.public_bytes(serialization.Encoding.DER)).decode()
    return key_pem, cert_pem, der_b64


def _signed_response(key_pem: str, cert_pem: str, *, in_response_to: str | None, role: str = "analyst") -> str:
    from onelogin.saml2.constants import OneLogin_Saml2_Constants as Saml
    from onelogin.saml2.utils import OneLogin_Saml2_Utils as Utils

    now = datetime.now(timezone.utc)
    instant = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    expires = (now + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    acs = SAML_ENV["AGENT_BOM_SAML_SP_ACS_URL"]
    issuer = SAML_ENV["AGENT_BOM_SAML_IDP_ENTITY_ID"]
    irt = f' InResponseTo="{in_response_to}"' if in_response_to else ""
    assertion_xml = (
        f'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a{uuid4().hex}" Version="2.0" IssueInstant="{instant}">'
        f"<saml:Issuer>{issuer}</saml:Issuer>"
        '<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.com</saml:NameID>'
        '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
        f'<saml:SubjectConfirmationData NotOnOrAfter="{expires}" Recipient="{acs}"{irt}/></saml:SubjectConfirmation></saml:Subject>'
        f'<saml:Conditions NotBefore="{instant}" NotOnOrAfter="{expires}"><saml:AudienceRestriction>'
        f"<saml:Audience>{SAML_ENV['AGENT_BOM_SAML_SP_ENTITY_ID']}</saml:Audience></saml:AudienceRestriction></saml:Conditions>"
        f'<saml:AuthnStatement AuthnInstant="{instant}" SessionIndex="_s1"><saml:AuthnContext><saml:AuthnContextClassRef>'
        "urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>"
        f'<saml:AttributeStatement><saml:Attribute Name="agent_bom_role"><saml:AttributeValue>{role}</saml:AttributeValue></saml:Attribute>'
        '<saml:Attribute Name="tenant_id"><saml:AttributeValue>tenant-alpha</saml:AttributeValue></saml:Attribute>'
        "</saml:AttributeStatement></saml:Assertion>"
    )
    signed_assertion = Utils.add_sign(assertion_xml, key_pem, cert_pem, sign_algorithm=Saml.RSA_SHA256, digest_algorithm=Saml.SHA256)
    assertion_text = signed_assertion.decode() if isinstance(signed_assertion, bytes) else signed_assertion
    response_xml = (
        f'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
        f'ID="_r{uuid4().hex}" Version="2.0" IssueInstant="{instant}" Destination="{acs}"{irt}><saml:Issuer>{issuer}</saml:Issuer>'
        '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
        f"{assertion_text}</samlp:Response>"
    )
    signed = Utils.add_sign(response_xml, key_pem, cert_pem, sign_algorithm=Saml.RSA_SHA256, digest_algorithm=Saml.SHA256)
    text = signed.decode() if isinstance(signed, bytes) else signed
    return base64.b64encode(text.encode()).decode()


@pytest.fixture
def idp(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    pytest.importorskip("onelogin.saml2.auth", reason="python3-saml not installed")
    key_pem, cert_pem, der_b64 = _signing_identity()
    monkeypatch.setenv("AGENT_BOM_SAML_IDP_X509_CERT", der_b64)
    return SimpleNamespace(
        sign=lambda in_response_to, role="analyst": _signed_response(key_pem, cert_pem, in_response_to=in_response_to, role=role)
    )


def test_real_start_issues_the_authn_request_the_cookie_is_bound_to(client: TestClient, idp: SimpleNamespace) -> None:
    response = client.get(START)

    assert response.status_code == 302, response.text
    query = parse_qs(urlsplit(response.headers["location"]).query)
    request_xml = zlib.decompress(base64.b64decode(query["SAMLRequest"][0]), -15).decode()
    request_id = client.cookies[SAML_LOGIN_COOKIE].split(".")[0]
    assert f'ID="{request_id}"' in request_xml
    assert f'AssertionConsumerServiceURL="{SAML_ENV["AGENT_BOM_SAML_SP_ACS_URL"]}"' in request_xml
    assert len(query["RelayState"][0].encode()) <= 80, "the HTTP-POST binding caps RelayState at 80 bytes"


def test_real_valid_response_from_the_browser_that_started_succeeds(client: TestClient, idp: SimpleNamespace, store: KeyStore) -> None:
    relay, request_id = _start(client)

    response = _post_form(client, SAMLResponse=idp.sign(request_id), RelayState=relay)

    assert response.status_code == 303, response.text
    assert response.headers["location"] == "/"
    assert _login_cookie_cleared(response)
    me = client.get("/v1/auth/me").json()
    assert (me["role"], me["tenant_id"], me["auth_method"]) == ("analyst", "tenant-alpha", "saml")


def test_real_valid_response_from_a_browser_without_the_cookie_is_refused(
    client: TestClient, idp: SimpleNamespace, store: KeyStore
) -> None:
    relay, request_id = _start(client)
    client.cookies.clear()

    response = _post_form(client, SAMLResponse=idp.sign(request_id), RelayState=relay)

    assert response.status_code == 401
    assert _no_session(response)
    assert store.list_keys("tenant-alpha") == []


def test_real_valid_response_with_another_logins_cookie_is_refused(client: TestClient, idp: SimpleNamespace, store: KeyStore) -> None:
    relay, request_id = _start(client)
    other_relay, other_request_id = _start(client)  # this browser's cookie now belongs to the second login

    first = _post_form(client, SAMLResponse=idp.sign(request_id), RelayState=relay)
    assert first.status_code == 401
    assert _no_session(first)
    assert store.list_keys("tenant-alpha") == []

    # The other login is untouched by the refusal.
    assert other_relay != relay and other_request_id != request_id
    assert _post_form(client, SAMLResponse=idp.sign(other_request_id), RelayState=other_relay).status_code == 303


def test_real_response_to_another_login_is_refused_despite_a_valid_cookie(
    client: TestClient, idp: SimpleNamespace, store: KeyStore
) -> None:
    relay, _request_id = _start(client)

    response = _post_form(client, SAMLResponse=idp.sign(f"ONELOGIN_{uuid4().hex}"), RelayState=relay)

    assert response.status_code == 401
    assert _no_session(response)
    assert _login_cookie_cleared(response)
    assert store.list_keys("tenant-alpha") == []


def test_real_response_without_in_response_to_is_refused(client: TestClient, idp: SimpleNamespace, store: KeyStore) -> None:
    relay, _request_id = _start(client)

    response = _post_form(client, SAMLResponse=idp.sign(None), RelayState=relay)

    assert response.status_code == 401
    assert "InResponseTo" in response.json()["detail"]
    assert _no_session(response)
    assert store.list_keys("tenant-alpha") == []


def test_real_replay_is_refused(client: TestClient, idp: SimpleNamespace, store: KeyStore) -> None:
    relay, request_id = _start(client)
    signed = idp.sign(request_id)
    login_cookie = client.cookies[SAML_LOGIN_COOKIE]
    assert _post_form(client, SAMLResponse=signed, RelayState=relay).status_code == 303
    keys_after_login = len(store.list_keys("tenant-alpha"))

    # Everything the browser held, sent again.
    client.cookies.clear()
    client.cookies.set(SAML_LOGIN_COOKIE, login_cookie)
    same_login = _post_form(client, SAMLResponse=signed, RelayState=relay)
    assert same_login.status_code == 401
    assert _no_session(same_login)

    # The response again, under a fresh login in this browser.
    client.cookies.clear()
    fresh_relay, _fresh_request_id = _start(client)
    fresh_login = _post_form(client, SAMLResponse=signed, RelayState=fresh_relay)
    assert fresh_login.status_code == 401
    assert _no_session(fresh_login)
    assert len(store.list_keys("tenant-alpha")) == keys_after_login


def test_real_verifier_refuses_tampered_and_unsigned_responses(client: TestClient, idp: SimpleNamespace, store: KeyStore) -> None:
    relay, request_id = _start(client)
    original = base64.b64decode(idp.sign(request_id, role="viewer")).decode()
    tampered = base64.b64encode(original.replace(">viewer<", ">admin<").encode()).decode()
    assert _post_form(client, SAMLResponse=tampered, RelayState=relay).status_code == 401

    relay, request_id = _start(client)
    unsigned = (
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
        f'ID="_r" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" InResponseTo="{request_id}" '
        'Destination="https://agent-bom.example.test/v1/auth/saml/login">'
        '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
        '<saml:Assertion ID="_a" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer>https://idp.example.test/metadata</saml:Issuer>'
        "<saml:Subject><saml:NameID>admin@example.com</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>"
    )
    response = _post_form(client, SAMLResponse=base64.b64encode(unsigned.encode()).decode(), RelayState=relay)
    assert response.status_code == 401
    assert _no_session(response)
    assert store.list_keys("tenant-alpha") == []


def test_real_idp_initiated_form_post_is_refused_when_json_allows_it(client: TestClient, idp: SimpleNamespace, monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_SAML_ALLOW_IDP_INITIATED", "1")

    response = _post_form(client, SAMLResponse=idp.sign(None))

    assert response.status_code == 401
    assert START in response.json()["detail"]
    assert _no_session(response)
