#!/usr/bin/env python3
"""Identity lane: the repo's Keycloak image with a synthetic realm.

Exercises API OIDC bearer tokens and the browser authorization-code flow, MCP
OAuth from docs/MCP_OAUTH.md including a token for another tenant being refused,
and SAML against the same issuer. Keycloak runs in production mode over TLS with
a throwaway CA, because the product refuses non-HTTPS issuers.
"""

from __future__ import annotations

import argparse
import base64
import html
import io
import json
import os
import re
import secrets
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent))

import identity_realm as realm  # noqa: E402
from common import REPO_ROOT, RESULTS_DIR, LaneResult, agent_bom_command, free_port, tail  # noqa: E402

KEYCLOAK_IMAGE = "agent-bom-qualification-keycloak"
KEYCLOAK_UID = 1000  # The official image runs as this user.
POSTGRES_IMAGE = "postgres:16-alpine"
NETWORK = "qualification-identity"
_MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json", "MCP-Protocol-Version": "2025-06-18"}


def _docker(*args: str, check: bool = True, timeout: float = 900) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=check, timeout=timeout)  # noqa: S603, S607


def _openssl(*args: str) -> None:
    subprocess.run(["openssl", *args], check=True, capture_output=True)  # noqa: S603, S607


def make_certificates(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    ca_key, ca_pem = str(directory / "ca.key"), str(directory / "ca.pem")
    server_key, server_csr = str(directory / "server.key"), str(directory / "server.csr")
    _openssl(
        "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=qualification-ca", "-keyout", ca_key, "-out", ca_pem
    )
    _openssl("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-keyout", server_key, "-out", server_csr)
    extensions = directory / "san.ext"
    extensions.write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\n", encoding="utf-8")
    _openssl(
        "x509", "-req", "-in", server_csr, "-CA", ca_pem, "-CAkey", ca_key, "-CAcreateserial", "-days", "2",
        "-extfile", str(extensions), "-out", str(directory / "server.pem"),
    )  # fmt: skip
    for path in directory.iterdir():
        path.chmod(0o644)
    directory.chmod(0o755)
    return directory / "ca.pem"


def realm_archive(realm_doc: dict[str, Any]) -> bytes:
    """The realm import as an in-memory tar, so its per-run credentials never reach the runner's disk."""
    body = json.dumps(realm_doc).encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        folder = tarfile.TarInfo("import")
        folder.type, folder.mode, folder.uid = tarfile.DIRTYPE, 0o750, KEYCLOAK_UID
        archive.addfile(folder)
        member = tarfile.TarInfo("import/realm.json")
        member.size, member.mode, member.uid = len(body), 0o600, KEYCLOAK_UID
        archive.addfile(member, io.BytesIO(body))
    return buffer.getvalue()


def start_keycloak(realm_doc: dict[str, Any], certs: Path) -> None:
    database_password = secrets.token_urlsafe(24)
    _docker("network", "create", NETWORK)
    _docker(
        "run",
        "-d",
        "--name",
        "qualification-kc-db",
        "--network",
        NETWORK,
        "-e",
        f"POSTGRES_PASSWORD={database_password}",
        "-e",
        "POSTGRES_USER=keycloak",
        "-e",
        "POSTGRES_DB=keycloak",
        POSTGRES_IMAGE,
    )
    _docker("build", "-t", KEYCLOAK_IMAGE, str(REPO_ROOT / "deploy" / "keycloak"))
    _docker(
        "create", "--name", "qualification-keycloak", "--network", NETWORK, "-p", "127.0.0.1:8443:8443",
        "-e", "KC_DB_URL=jdbc:postgresql://qualification-kc-db:5432/keycloak",
        "-e", "KC_DB_USERNAME=keycloak", "-e", f"KC_DB_PASSWORD={database_password}",
        "-e", f"KC_HOSTNAME={realm.ISSUER_ORIGIN}", "-e", "KC_HOSTNAME_STRICT=true", "-e", "KC_CACHE=local",
        "-e", "KC_HTTPS_CERTIFICATE_FILE=/certs/server.pem", "-e", "KC_HTTPS_CERTIFICATE_KEY_FILE=/certs/server.key",
        "-e", "KC_BOOTSTRAP_ADMIN_USERNAME=qualification-admin", "-e", f"KC_BOOTSTRAP_ADMIN_PASSWORD={secrets.token_urlsafe(24)}",
        "-v", f"{certs}:/certs:ro",
        KEYCLOAK_IMAGE, "start", "--optimized", "--import-realm",
    )  # fmt: skip
    subprocess.run(  # noqa: S603, S607
        ["docker", "cp", "-", "qualification-keycloak:/opt/keycloak/data"],
        input=realm_archive(realm_doc),
        capture_output=True,
        check=True,
        timeout=60,
    )
    _docker("start", "qualification-keycloak")


def stop_keycloak() -> None:
    for name in ("qualification-keycloak", "qualification-kc-db"):
        _docker("rm", "-f", name, check=False)
    _docker("network", "rm", NETWORK, check=False)


def wait_for_issuer(ca: Path, timeout: float = 300) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if httpx.get(f"{realm.ISSUER}/.well-known/openid-configuration", verify=str(ca), timeout=5).status_code == 200:
                return True
        except httpx.HTTPError:
            pass  # Keycloak is still starting; the loop retries until its deadline.
        time.sleep(3)
    return False


class Issuer:
    def __init__(self, ca: Path, realm_secrets: realm.RealmSecrets) -> None:
        self.ca = str(ca)
        self.secrets = realm_secrets

    def token(self, client_id: str) -> str:
        response = httpx.post(
            f"{realm.ISSUER}/protocol/openid-connect/token",
            data={"grant_type": "client_credentials"},
            auth=(client_id, self.secrets.probe(client_id)),
            verify=self.ca,
            timeout=30,
        )
        response.raise_for_status()
        return str(response.json()["access_token"])

    def revoke(self, client_id: str, token: str) -> int:
        response = httpx.post(
            f"{realm.ISSUER}/protocol/openid-connect/revoke",
            data={"token": token, "token_type_hint": "access_token"},
            auth=(client_id, self.secrets.probe(client_id)),
            verify=self.ca,
            timeout=30,
        )
        return response.status_code


def claims_of(token: str) -> dict[str, Any]:
    """Read claims for fixture setup only; the product under test verifies signatures."""
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def tamper(token: str) -> str:
    header, payload, signature = token.split(".")
    flipped = "A" if signature[10] != "A" else "B"
    return f"{header}.{payload}.{signature[:10]}{flipped}{signature[11:]}"


class Service:
    """A product process with its log kept for the lane's artifact."""

    def __init__(self, name: str, arguments: list[str], env: dict[str, str]) -> None:
        log_dir = RESULTS_DIR / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = log_dir / f"{name}.log"
        self._log = self.log_path.open("wb")
        self.process = subprocess.Popen(agent_bom_command(*arguments), env=env, stdout=self._log, stderr=subprocess.STDOUT)  # noqa: S603

    def wait_ready(self, url: str, timeout: float = 120) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and self.process.poll() is None:
            try:
                if httpx.get(url, timeout=3).status_code < 500:
                    return True
            except httpx.HTTPError:
                pass  # Not listening yet; the loop retries until its deadline.
            time.sleep(1)
        return False

    def stop(self) -> None:
        self.process.terminate()
        try:
            self.process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.process.kill()
        self._log.close()

    def log_tail(self) -> str:
        return tail(self.log_path.read_text(encoding="utf-8", errors="replace"), 15)


def api_env(workdir: Path, ca: Path, port: int, realm_secrets: realm.RealmSecrets, idp_certificate: str) -> dict[str, str]:
    secret_file = workdir / "oidc-client-secret"
    secret_file.write_text(realm_secrets.browser_client, encoding="utf-8")
    secret_file.chmod(0o600)
    return {
        **os.environ,
        "HOME": str(workdir / "api-home"),
        "AGENT_BOM_STATE_DIR": str(workdir / "api-home" / ".agent-bom"),
        "AGENT_BOM_DB": str(workdir / "api.db"),
        "SSL_CERT_FILE": str(ca),
        "AGENT_BOM_ALLOW_PRIVATE_EGRESS_URLS": "1",
        "AGENT_BOM_OIDC_ISSUER": realm.ISSUER,
        "AGENT_BOM_OIDC_AUDIENCE": realm.API_AUDIENCE,
        "AGENT_BOM_OIDC_JWKS_URI": f"{realm.ISSUER}/protocol/openid-connect/certs",
        "AGENT_BOM_OIDC_CLIENT_ID": realm.BROWSER_CLIENT,
        "AGENT_BOM_OIDC_CLIENT_SECRET_FILE": str(secret_file),
        "AGENT_BOM_OIDC_REDIRECT_URI": f"http://127.0.0.1:{port}/v1/auth/oidc/callback",
        "AGENT_BOM_OIDC_SCOPES": "openid",
        "AGENT_BOM_SAML_IDP_ENTITY_ID": realm.ISSUER,
        "AGENT_BOM_SAML_IDP_SSO_URL": f"{realm.ISSUER}/protocol/saml",
        "AGENT_BOM_SAML_IDP_X509_CERT": idp_certificate,
        "AGENT_BOM_SAML_SP_ENTITY_ID": realm.SAML_SP_ENTITY,
        "AGENT_BOM_SAML_SP_ACS_URL": f"http://127.0.0.1:{port}/v1/auth/saml/login",
    }


def exercise_api_bearer(result: LaneResult, base: str, issuer: Issuer, mcp_token: str) -> None:
    token_a, token_b = issuer.token("api-tenant-a"), issuer.token("api-tenant-b")

    def get(path: str, token: str | None) -> httpx.Response:
        return httpx.get(f"{base}{path}", headers={"Authorization": f"Bearer {token}"} if token else {}, timeout=60)

    me = get("/v1/auth/me", token_a)
    body = me.json() if me.status_code == 200 else {}
    result.check("oidc_bearer_is_accepted", me.status_code == 200, f"HTTP {me.status_code} {me.text[:300]}")
    result.check("oidc_bearer_carries_tenant", body.get("tenant_id") == "tenant-a", str(body)[:300])
    result.check("oidc_refuses_missing_token", get("/v1/jobs", None).status_code == 401, "no credential")
    result.check("oidc_refuses_tampered_signature", get("/v1/jobs", tamper(token_a)).status_code == 401, "flipped signature byte")
    result.check("oidc_refuses_other_audience", get("/v1/jobs", mcp_token).status_code == 401, "MCP audience token")
    report = {
        "scan_id": "qualification-tenant-a",
        "agents": [{"name": "a", "type": "custom", "mcp_servers": []}],
        "blast_radius": [],
        "source_id": "identity",
    }
    pushed = httpx.post(f"{base}/v1/results/push", json=report, headers={"Authorization": f"Bearer {token_a}"}, timeout=60)
    job_id = pushed.json().get("job_id") if pushed.status_code in (201, 202) else None
    result.check("oidc_analyst_can_write", bool(job_id), f"HTTP {pushed.status_code} {pushed.text[:300]}")
    jobs_a, jobs_b = get("/v1/jobs", token_a), get("/v1/jobs", token_b)
    result.check("tenant_reads_its_own_job", job_id is not None and job_id in jobs_a.text, f"HTTP {jobs_a.status_code}")
    result.check(
        "other_tenant_cannot_list_job", jobs_b.status_code == 200 and (job_id or "missing") not in jobs_b.text, f"HTTP {jobs_b.status_code}"
    )
    direct = get(f"/v1/scan/{job_id}", token_b)
    result.check("other_tenant_cannot_read_job", direct.status_code in (403, 404), f"HTTP {direct.status_code}")


def _login_form(client: httpx.Client, start_url: str) -> tuple[str, httpx.Response]:
    page = client.get(start_url)
    match = re.search(r'action="([^"]+)"', page.text)
    if page.status_code != 200 or not match:
        raise RuntimeError(f"no Keycloak login form: HTTP {page.status_code} {page.text[:300]}")
    return html.unescape(match.group(1)), page


def exercise_browser_login(result: LaneResult, base: str, ca: Path, realm_secrets: realm.RealmSecrets) -> None:
    with httpx.Client(verify=str(ca), follow_redirects=False, timeout=60) as client:
        start = client.get(f"{base}/v1/auth/oidc/login")
        if not result.check(
            "oidc_login_redirects_to_issuer",
            start.status_code == 302 and start.headers.get("location", "").startswith(realm.ISSUER),
            f"HTTP {start.status_code} {start.text[:300]}",
        ):
            return
        location = start.headers["location"]
        result.check("oidc_login_uses_pkce", "code_challenge_method=S256" in location, location.split("?")[0])
        action, _page = _login_form(client, location)
        wrong = client.post(action, data={"username": realm.USER_NAME, "password": "not-the-password"})
        result.check("issuer_refuses_wrong_password", wrong.status_code == 200, f"HTTP {wrong.status_code}")
        action = html.unescape(re.search(r'action="([^"]+)"', wrong.text).group(1))  # type: ignore[union-attr]
        issued = client.post(action, data={"username": realm.USER_NAME, "password": realm_secrets.user_password})
        callback = issued.headers.get("location", "")
        if not result.check(
            "issuer_redirects_with_code",
            issued.status_code == 302 and "/v1/auth/oidc/callback" in callback,
            f"HTTP {issued.status_code} {issued.text[:300]}",
        ):
            return
        session = client.get(callback)
        result.check("oidc_callback_creates_session", session.status_code == 302, f"HTTP {session.status_code} {session.text[:400]}")
        me = client.get(f"{base}/v1/auth/me")
        body = me.json() if me.status_code == 200 else {}
        result.check(
            "session_authenticates_api",
            me.status_code == 200 and body.get("tenant_id") == realm.USER_TENANT,
            f"HTTP {me.status_code} {str(body)[:300]}",
        )
        jobs = client.get(f"{base}/v1/jobs")
        result.check("session_reads_api", jobs.status_code == 200, f"HTTP {jobs.status_code}")
        replay = client.get(callback)
        result.check("oidc_callback_refuses_replay", replay.status_code == 401, f"HTTP {replay.status_code}")


def _saml_response(client: httpx.Client, realm_secrets: realm.RealmSecrets, relay_state: str) -> str:
    action, _page = _login_form(client, f"{realm.ISSUER}/protocol/saml/clients/{realm.SAML_URL_NAME}?RelayState={relay_state}")
    posted = client.post(action, data={"username": realm.USER_NAME, "password": realm_secrets.user_password})
    match = re.search(r'name="SAMLResponse"\s+value="([^"]+)"', posted.text)
    if not match:
        raise RuntimeError(f"Keycloak returned no SAMLResponse: HTTP {posted.status_code} {posted.text[:300]}")
    return html.unescape(match.group(1))


def exercise_saml(result: LaneResult, base: str, ca: Path, realm_secrets: realm.RealmSecrets) -> None:
    metadata = httpx.get(f"{base}/v1/auth/saml/metadata", timeout=30)
    if metadata.status_code == 503 and "saml" in metadata.text.lower() and "extra" in metadata.text.lower():
        result.skip("saml", f"python3-saml unavailable on this runner: {metadata.text[:200]}")
        return
    result.check(
        "saml_metadata_served",
        metadata.status_code == 200 and realm.SAML_SP_ENTITY in metadata.text,
        f"HTTP {metadata.status_code} {metadata.text[:300]}",
    )
    relay = httpx.post(f"{base}/v1/auth/saml/relay-state", timeout=30)
    relay_state = relay.json().get("relay_state", "") if relay.status_code == 200 else ""
    result.check("saml_relay_state_issued", bool(relay_state), f"HTTP {relay.status_code}")
    with httpx.Client(verify=str(ca), follow_redirects=True, timeout=60) as client:
        saml_response = _saml_response(client, realm_secrets, relay_state)
    # The IdP's browser form posts urlencoded to the ACS URL it was given.
    form_post = httpx.post(
        f"{base}/v1/auth/saml/login", data={"SAMLResponse": saml_response, "RelayState": relay_state}, timeout=60, follow_redirects=False
    )
    result.measurements["saml_form_post_status"] = form_post.status_code
    if form_post.status_code not in (200, 201, 302, 303):
        result.defect(
            "saml-acs-rejects-idp-form-post",
            f"The SP ACS URL answers HTTP {form_post.status_code} to the urlencoded POST an IdP browser form sends; it only accepts JSON",
            'curl -i -X POST "$API/v1/auth/saml/login" --data-urlencode "SAMLResponse=$RESPONSE" --data-urlencode "RelayState=$RELAY"',
        )
    relay = httpx.post(f"{base}/v1/auth/saml/relay-state", timeout=30)
    relay_state = relay.json().get("relay_state", "")
    with httpx.Client(verify=str(ca), follow_redirects=True, timeout=60) as client:
        saml_response = _saml_response(client, realm_secrets, relay_state)
    login = httpx.post(f"{base}/v1/auth/saml/login", json={"saml_response": saml_response, "relay_state": relay_state}, timeout=60)
    body = login.json() if login.status_code == 201 else {}
    result.check("saml_assertion_is_verified", login.status_code == 201, f"HTTP {login.status_code} {login.text[:400]}")
    result.check(
        "saml_maps_tenant_and_role",
        body.get("tenant_id") == realm.USER_TENANT and body.get("role") == realm.ROLE,
        str({k: body.get(k) for k in ("tenant_id", "role", "subject")}),
    )
    if body.get("raw_key"):
        jobs = httpx.get(f"{base}/v1/jobs", headers={"Authorization": f"Bearer {body['raw_key']}"}, timeout=30)
        result.check("saml_key_reads_api", jobs.status_code == 200, f"HTTP {jobs.status_code}")
    replay = httpx.post(f"{base}/v1/auth/saml/login", json={"saml_response": saml_response, "relay_state": relay_state}, timeout=60)
    result.check("saml_refuses_replay", replay.status_code == 401, f"HTTP {replay.status_code}")
    forged = base64.b64encode(base64.b64decode(saml_response).replace(realm.USER_TENANT.encode(), b"tenant-b")).decode()
    relay = httpx.post(f"{base}/v1/auth/saml/relay-state", timeout=30).json().get("relay_state", "")
    tampered = httpx.post(f"{base}/v1/auth/saml/login", json={"saml_response": forged, "relay_state": relay}, timeout=60)
    result.check("saml_refuses_tampered_tenant", tampered.status_code == 401, f"HTTP {tampered.status_code} {tampered.text[:200]}")


def mcp_env(workdir: Path, ca: Path, subjects: list[str], realm_secrets: realm.RealmSecrets) -> dict[str, str]:
    secret_file = workdir / "mcp-introspection"
    secret_file.write_text(realm_secrets.introspection_client, encoding="utf-8")
    secret_file.chmod(0o600)
    env = {key: value for key, value in os.environ.items() if not key.startswith("AGENT_BOM_MCP_")}
    env.update(
        HOME=str(workdir / "mcp-home"),
        AGENT_BOM_STATE_DIR=str(workdir / "mcp-home" / ".agent-bom"),
        SSL_CERT_FILE=str(ca),
        AGENT_BOM_ALLOW_PRIVATE_EGRESS_URLS="1",
        AGENT_BOM_MCP_PUBLIC_URL=realm.MCP_AUDIENCE.removesuffix("/mcp"),
        AGENT_BOM_MCP_OAUTH_ISSUER=realm.ISSUER,
        AGENT_BOM_MCP_OAUTH_AUDIENCE=realm.MCP_AUDIENCE,
        AGENT_BOM_MCP_OAUTH_JWKS_URI=f"{realm.ISSUER}/protocol/openid-connect/certs",
        AGENT_BOM_MCP_OAUTH_SUBJECTS=",".join(subjects),
        AGENT_BOM_MCP_TENANT_ID="tenant-a",
        AGENT_BOM_MCP_OAUTH_INTROSPECTION_URL=f"{realm.ISSUER}/protocol/openid-connect/token/introspect",
        AGENT_BOM_MCP_OAUTH_INTROSPECTION_CLIENT_ID=realm.MCP_AUDIENCE,
        AGENT_BOM_MCP_OAUTH_INTROSPECTION_CLIENT_SECRET_FILE=str(secret_file),
    )
    return env


def _rpc_reply(response: httpx.Response) -> dict[str, Any]:
    if "event-stream" in response.headers.get("content-type", ""):
        for line in response.text.splitlines():
            if line.startswith("data:"):
                return json.loads(line[5:])
        return {}
    return response.json() if response.content else {}


class McpClient:
    def __init__(self, url: str, token: str | None) -> None:
        self.url = url
        self.headers = dict(_MCP_HEADERS)
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

    def post(self, method: str, params: dict[str, Any] | None = None, message_id: int | None = 1) -> httpx.Response:
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        if message_id is not None:
            message["id"] = message_id
        return httpx.post(self.url, json=message, headers=self.headers, timeout=60)

    def initialize(self) -> httpx.Response:
        params = {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "qualification", "version": "1"}}
        response = self.post("initialize", params)
        session = response.headers.get("mcp-session-id")
        if session:
            self.headers["Mcp-Session-Id"] = session
        if response.status_code == 200:
            self.post("notifications/initialized", message_id=None)
        return response


def exercise_mcp(result: LaneResult, issuer: Issuer, base: str) -> None:
    url = f"{base}/mcp"
    anonymous = McpClient(url, None).initialize()
    result.check("mcp_refuses_anonymous", anonymous.status_code == 401, f"HTTP {anonymous.status_code}")
    result.check(
        "mcp_challenge_names_metadata",
        "resource_metadata" in anonymous.headers.get("www-authenticate", ""),
        anonymous.headers.get("www-authenticate", ""),
    )
    metadata = httpx.get(f"{base}/.well-known/oauth-protected-resource/mcp", timeout=30)
    body = metadata.json() if metadata.status_code == 200 else {}
    result.check("mcp_metadata_names_issuer", realm.ISSUER in json.dumps(body) and realm.MCP_AUDIENCE in json.dumps(body), str(body)[:300])
    card = httpx.get(f"{base}/.well-known/mcp/server-card.json", timeout=30)
    result.check(
        "mcp_card_advertises_oauth2", card.status_code == 200 and "oauth2" in card.text, f"HTTP {card.status_code} {card.text[:200]}"
    )

    token_a = issuer.token("probe-tenant-a")
    client = McpClient(url, token_a)
    initialized = client.initialize()
    result.check("mcp_accepts_tenant_token", initialized.status_code == 200, f"HTTP {initialized.status_code} {initialized.text[:300]}")
    listed = client.post("tools/list", message_id=2)
    tools = (_rpc_reply(listed).get("result") or {}).get("tools", []) if listed.status_code == 200 else []
    names = {tool.get("name") for tool in tools}
    result.measurements["mcp_tools_listed"] = len(names)
    result.check("mcp_lists_tools_with_token", bool(names), f"HTTP {listed.status_code} {listed.text[:300]}")
    result.check("mcp_catalog_excludes_writes", "scan" not in names, sorted(str(name) for name in names)[:30])

    other_tenant = McpClient(url, issuer.token("probe-tenant-b")).initialize()
    result.check(
        "mcp_refuses_other_tenant_token", other_tenant.status_code == 401, f"HTTP {other_tenant.status_code} {other_tenant.text[:200]}"
    )
    other_audience = McpClient(url, issuer.token("probe-other-audience")).initialize()
    result.check("mcp_refuses_other_audience", other_audience.status_code == 401, f"HTTP {other_audience.status_code}")
    unapproved = McpClient(url, issuer.token("probe-unapproved")).initialize()
    result.check("mcp_refuses_unapproved_subject", unapproved.status_code == 401, f"HTTP {unapproved.status_code}")
    tampered = McpClient(url, tamper(token_a)).initialize()
    result.check("mcp_refuses_tampered_signature", tampered.status_code == 401, f"HTTP {tampered.status_code}")

    expiring = issuer.token("probe-expiring")
    fresh = McpClient(url, expiring).initialize()
    result.check("mcp_accepts_short_token_while_valid", fresh.status_code == 200, f"HTTP {fresh.status_code}")
    time.sleep(7)
    expired = McpClient(url, expiring).initialize()
    result.check("mcp_refuses_expired_token", expired.status_code == 401, f"HTTP {expired.status_code}")

    revoked_token = issuer.token("probe-revoked")
    before = McpClient(url, revoked_token).initialize()
    revoke_status = issuer.revoke("probe-revoked", revoked_token)
    after = McpClient(url, revoked_token).initialize()
    result.check(
        "mcp_enforces_revocation",
        before.status_code == 200 and revoke_status == 200 and after.status_code == 401,
        f"before {before.status_code}, revoke {revoke_status}, after {after.status_code}",
    )
    second = McpClient(url, issuer.token("probe-tenant-a")).initialize()
    result.check("mcp_accepts_newly_issued_token", second.status_code == 200, f"HTTP {second.status_code}")

    with_tenant = [tool for tool in tools if "tenant_id" in ((tool.get("inputSchema") or {}).get("properties") or {})]
    result.measurements["mcp_tools_with_tenant_argument"] = len(with_tenant)
    if with_tenant:
        called = client.post("tools/call", {"name": with_tenant[0]["name"], "arguments": {"tenant_id": "tenant-b"}}, message_id=3)
        text = json.dumps(_rpc_reply(called))
        result.check(
            "mcp_refuses_tenant_argument",
            "does not authorize" in text or '"isError": true' in text,
            f"{with_tenant[0]['name']}: {text[:400]}",
        )
    else:
        result.skip("MCP tenant argument", "no catalog tool exposes a tenant_id argument, so the argument path was not reachable")


def _idp_certificate(ca: Path) -> str:
    descriptor = httpx.get(f"{realm.ISSUER}/protocol/saml/descriptor", verify=str(ca), timeout=30)
    match = re.search(r"<(?:\w+:)?X509Certificate>([^<]+)<", descriptor.text)
    if not match:
        raise RuntimeError("Keycloak SAML descriptor has no signing certificate")
    return match.group(1).strip()


def run(result: LaneResult, workdir: Path) -> None:
    api_port, mcp_port = free_port(), free_port()
    realm_secrets = realm.RealmSecrets()
    realm_doc = realm.build_realm(
        realm_secrets,
        redirect_uri=f"http://127.0.0.1:{api_port}/v1/auth/oidc/callback",
        saml_acs_url=f"http://127.0.0.1:{api_port}/v1/auth/saml/login",
    )
    ca = make_certificates(workdir / "certs")
    started = time.monotonic()
    start_keycloak(realm_doc, workdir / "certs")
    ready = wait_for_issuer(ca)
    result.measurements["keycloak_ready_seconds"] = round(time.monotonic() - started, 1)
    if not result.check(
        "keycloak_issuer_ready", ready, _docker("logs", "--tail", "25", "qualification-keycloak", check=False).stderr[-1500:]
    ):
        return
    issuer = Issuer(ca, realm_secrets)
    subjects = [claims_of(issuer.token(name))["sub"] for name in realm.MCP_PROBES if name != "probe-unapproved"]
    token_claims = claims_of(issuer.token("probe-tenant-a"))
    result.check(
        "realm_issues_documented_claims",
        token_claims.get("tenant_id") == "tenant-a"
        and "read" in str(token_claims.get("scope"))
        and realm.MCP_AUDIENCE in json.dumps(token_claims.get("aud")),
        {key: token_claims.get(key) for key in ("aud", "scope", "tenant_id")},
    )

    for home in ("api-home", "mcp-home"):
        (workdir / home).mkdir()
    api = Service(
        "identity-api",
        ["api", "--host", "127.0.0.1", "--port", str(api_port)],
        api_env(workdir, ca, api_port, realm_secrets, _idp_certificate(ca)),
    )
    mcp = Service(
        "identity-mcp",
        ["mcp", "server", "--transport", "streamable-http", "--host", "127.0.0.1", "--port", str(mcp_port)],
        mcp_env(workdir, ca, subjects, realm_secrets),
    )
    try:
        api_base, mcp_base = f"http://127.0.0.1:{api_port}", f"http://127.0.0.1:{mcp_port}"
        api_ready = result.check("api_starts_with_oidc", api.wait_ready(f"{api_base}/health"), api.log_tail())
        mcp_ready = result.check(
            "mcp_starts_with_oauth", mcp.wait_ready(f"{mcp_base}/.well-known/oauth-protected-resource/mcp"), mcp.log_tail()
        )
        if api_ready:
            exercise_api_bearer(result, api_base, issuer, issuer.token("probe-tenant-a"))
            exercise_browser_login(result, api_base, ca, realm_secrets)
            exercise_saml(result, api_base, ca, realm_secrets)
        if mcp_ready:
            exercise_mcp(result, issuer, mcp_base)
    finally:
        api.stop()
        mcp.stop()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.parse_args()
    result = LaneResult("identity", "keycloak")
    with tempfile.TemporaryDirectory(prefix="qualification-identity-") as tmp:
        try:
            run(result, Path(tmp).resolve())
        except Exception as exc:  # noqa: BLE001 - a lane records its own failure before exiting
            result.check("lane_completed", False, f"{type(exc).__name__}: {exc}")
        finally:
            logs = _docker("logs", "--tail", "400", "qualification-keycloak", check=False)
            (RESULTS_DIR / "logs").mkdir(parents=True, exist_ok=True)
            (RESULTS_DIR / "logs" / "keycloak.log").write_text(logs.stdout + logs.stderr, encoding="utf-8")
            stop_keycloak()
    return result.write()


if __name__ == "__main__":
    raise SystemExit(main())
