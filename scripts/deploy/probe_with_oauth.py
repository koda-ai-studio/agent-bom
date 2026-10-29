#!/usr/bin/env python3
"""Obtain a short-lived read token and run the deployment probe without printing it."""

from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from urllib.parse import quote, urlencode, urlsplit


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("OAuth token endpoint redirects are not allowed")


OAUTH_SETTING_NAMES = ("ISSUER", "TOKEN_URL", "CLIENT_ID", "CLIENT_SECRET", "AUDIENCE")


def probe_environment(environ: dict[str, str]) -> dict[str, str]:
    env = dict(environ)
    names = OAUTH_SETTING_NAMES
    settings = {name: env.get("MCP_PROBE_OAUTH_" + name, "").strip() for name in names}
    if not any(settings.values()):
        env["AGENT_BOM_DEPLOYMENT_BEARER_TOKEN"] = env.get("RAILWAY_MCP_BEARER_TOKEN", "")
        return env
    if not all(settings.values()):
        raise ValueError("Incomplete OAuth probe configuration")
    issuer, endpoint = (urlsplit(settings[k]) for k in ("ISSUER", "TOKEN_URL"))
    for value in (issuer, endpoint):
        if value.scheme != "https" or not value.hostname or value.username or value.password or value.query or value.fragment:
            raise ValueError("OAuth probe endpoints require HTTPS without embedded credentials")
    if issuer.netloc != endpoint.netloc:
        raise ValueError("OAuth token endpoint must use the configured issuer origin")
    credentials = ":".join(quote(settings[k], safe="") for k in ("CLIENT_ID", "CLIENT_SECRET"))
    request = urllib.request.Request(
        settings["TOKEN_URL"],
        data=urlencode({"grant_type": "client_credentials", "scope": "read", "resource": settings["AUDIENCE"]}).encode(),
        headers={
            "Authorization": "Basic " + base64.b64encode(credentials.encode()).decode(),
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=15) as response:  # noqa: S310 — operator-pinned HTTPS origin, redirects disabled
        body = response.read(65537)
    if len(body) > 65536:
        raise ValueError("OAuth token response exceeds size limit")
    result = json.loads(body)
    ttl = result.get("expires_in")
    token = result.get("access_token")
    if result.get("token_type", "").lower() != "bearer" or type(ttl) is not int or not 0 < ttl <= 3600:
        raise ValueError("OAuth probe requires a bearer token with a lifetime of at most one hour")
    if not isinstance(token, str) or not token or len(token) > 16384 or any(c.isspace() for c in token):
        raise ValueError("Invalid OAuth access token")
    env["AGENT_BOM_DEPLOYMENT_BEARER_TOKEN"] = token
    # The probe process needs the access token, never the client secret.
    for name in names:
        env.pop("MCP_PROBE_OAUTH_" + name, None)
    return env


# Outcome classes the deploy job reads back: only an identity-provider outage
# is "deploy succeeded, probe deferred"; everything else fails the check.
OUTCOME_AUTH_PROVIDER_UNAVAILABLE = "auth_provider_unavailable"
OUTCOME_CREDENTIAL_REJECTED = "credential_rejected"
OUTCOME_PROBE_CONFIGURATION = "probe_configuration"
OUTCOME_PROBE_FAILED = "probe_failed"


def classify_token_failure(exc: BaseException) -> tuple[str, str]:
    """Name the token-endpoint failure without the URL, reason phrase or response body."""
    if isinstance(exc, urllib.error.HTTPError):
        detail = f"OAuth token endpoint returned HTTP {exc.code}"
        return (OUTCOME_AUTH_PROVIDER_UNAVAILABLE if exc.code >= 500 else OUTCOME_CREDENTIAL_REJECTED), detail
    if isinstance(exc, urllib.error.URLError):
        return OUTCOME_AUTH_PROVIDER_UNAVAILABLE, f"OAuth token endpoint unreachable ({type(exc.reason).__name__})"
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return OUTCOME_AUTH_PROVIDER_UNAVAILABLE, "OAuth token endpoint timed out"
    if isinstance(exc, OSError):
        return OUTCOME_AUTH_PROVIDER_UNAVAILABLE, f"OAuth token endpoint unreachable ({type(exc).__name__})"
    if isinstance(exc, ValueError) and not isinstance(exc, json.JSONDecodeError):
        return OUTCOME_PROBE_CONFIGURATION, str(exc)
    return OUTCOME_PROBE_CONFIGURATION, f"OAuth token response rejected ({type(exc).__name__})"


def report_outcome(outcome: str, detail: str) -> None:
    print(f"deployment probe: {detail} [outcome={outcome}]", file=sys.stderr)
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as handle:
            handle.write(f"probe_outcome={outcome}\nprobe_detail={detail}\n")


def main() -> int:
    environ = dict(os.environ)
    oauth_configured = any(environ.get("MCP_PROBE_OAUTH_" + name, "").strip() for name in OAUTH_SETTING_NAMES)
    if not oauth_configured and not environ.get("RAILWAY_MCP_BEARER_TOKEN", "").strip():
        report_outcome(OUTCOME_PROBE_CONFIGURATION, "no probe credential: RAILWAY_MCP_BEARER_TOKEN is empty and MCP_PROBE_OAUTH_* unset")
        return 1
    try:
        env = probe_environment(environ)
    except Exception as exc:  # noqa: BLE001 — fail closed; the classification never includes credentials or the issuer response
        outcome, detail = classify_token_failure(exc)
        print("Unable to obtain the configured deployment probe credential", file=sys.stderr)
        report_outcome(outcome, detail)
        return 1
    arguments = sys.argv[1:]
    if arguments[:1] == ["--"]:
        arguments = arguments[1:]
    status = subprocess.run([sys.executable, "-m", "agent_bom.deployment_probe", *arguments], env=env, check=False).returncode
    if status != 0:
        report_outcome(OUTCOME_PROBE_FAILED, f"MCP probe exited {status}; see the initialize status above")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
