"""Auth runtime state."""

from __future__ import annotations

from dataclasses import dataclass

_AUTH_RUNTIME_STATUS: dict[str, object] = {
    "auth_required": True,
    "auth_configured": False,
    "configured_modes": [],
    "recommended_ui_mode": "configure_auth",
    "unauthenticated_allowed": False,
}


class AuthPostureError(RuntimeError):
    """Raised when the derived auth posture is internally contradictory.

    A contradictory posture is a fail-fast startup error (surfaced by the CLI
    serve/api gate) rather than a silent coexistence that only breaks at request
    time.
    """


@dataclass(frozen=True)
class AuthPosture:
    """The single derived view of control-plane authentication posture.

    Every reader — the CLI serve gate, ``/health``/operator surfaces (via the
    runtime status), and the middleware — consumes this one object instead of
    re-deriving the same facts from the environment. The boolean fields are the
    raw credential-source facts (derived once by ``derive_auth_posture``); the
    properties express the precedence order and the two aggregate views the
    readers need.
    """

    listener_host: str
    listener_loopback: bool
    api_key: bool
    oidc_bearer: bool
    oidc_browser: bool
    snowflake_oauth: bool
    scim_bearer: bool
    saml: bool
    trusted_proxy: bool
    anonymous_allowed: bool
    oidc_config_invalid: bool = False
    oidc_config_error: str | None = None

    @property
    def sources(self) -> tuple[str, ...]:
        """Effective credential sources in resolver precedence order."""
        ordered: list[str] = []
        if self.scim_bearer:
            ordered.append("scim_bearer")
        if self.trusted_proxy:
            ordered.append("trusted_proxy")
        if self.oidc_bearer:
            ordered.append("oidc_bearer")
        if self.api_key:
            ordered.append("api_key")
        if self.oidc_browser:
            ordered.append("oidc_browser")
        if self.snowflake_oauth:
            ordered.append("snowflake_oauth")
        if self.saml:
            ordered.append("saml_sso")
        return tuple(ordered)

    @property
    def auth_configured(self) -> bool:
        """True when any credential source (including browser SSO) is configured."""
        return bool(self.sources)

    @property
    def programmatic_auth_configured(self) -> bool:
        """The serve-gate view: excludes browser-interactive SSO.

        ``oidc_browser`` / ``snowflake_oauth`` are browser-login flows that do
        not gate programmatic API access, so the non-loopback serve gate does
        not treat them as satisfying the auth requirement (unchanged behavior).
        """
        return self.api_key or self.oidc_bearer or self.scim_bearer or self.saml or self.trusted_proxy

    @property
    def configured_modes(self) -> list[str]:
        """Operator/UI mode list — ordering preserved for existing consumers."""
        modes: list[str] = []
        if self.trusted_proxy:
            modes.append("trusted_proxy")
        if self.oidc_browser:
            modes.append("oidc_browser")
        if self.snowflake_oauth:
            modes.append("snowflake_oauth")
        if self.oidc_bearer:
            modes.append("oidc_bearer")
        if self.api_key:
            modes.append("api_key")
        if self.scim_bearer:
            modes.append("scim_provisioning")
        if self.saml:
            modes.append("saml_sso")
        return modes

    @property
    def auth_required(self) -> bool:
        # An explicit unauthenticated opt-in means anonymous callers are served
        # as NO_AUTH_ROLE, so authentication is not *required* — even when
        # credentials are also configured for callers who want to elevate.
        return not self.anonymous_allowed

    @property
    def recommended_ui_mode(self) -> str:
        if self.anonymous_allowed and not self.auth_configured:
            return "no_auth"
        if self.trusted_proxy:
            return "reverse_proxy_oidc"
        if self.oidc_browser:
            return "oidc_browser"
        if self.snowflake_oauth:
            return "snowflake_oauth"
        if self.oidc_bearer:
            return "oidc_bearer"
        if self.saml or self.api_key:
            # SAML SSO completes at the IdP and mints a short-lived session API
            # key, so the dashboard uses the same session-key login surface.
            return "session_api_key"
        return "configure_auth"

    def runtime_status(self) -> dict[str, object]:
        """Project to the operator/UI runtime-status dict (the /health source)."""
        return {
            "auth_required": self.auth_required,
            "auth_configured": self.auth_configured,
            "configured_modes": self.configured_modes,
            "recommended_ui_mode": self.recommended_ui_mode,
            "unauthenticated_allowed": self.anonymous_allowed,
        }

    def summary_line(self) -> str:
        """One structured line summarizing the posture for the startup log."""
        sources = ">".join(self.sources) if self.sources else "none"
        scope = "unknown" if self.listener_host == "unknown" else ("loopback" if self.listener_loopback else "non-loopback")
        return (
            f"auth posture: sources=[{sources}] "
            f"anonymous={'on' if self.anonymous_allowed else 'off'} "
            f"listener={self.listener_host}({scope}) "
            f"trusted_proxy={'usable' if self.trusted_proxy else 'off'} "
            f"oidc={'invalid' if self.oidc_config_invalid else ('configured' if self.oidc_bearer else 'off')}"
        )


_EMPTY_AUTH_POSTURE = AuthPosture(
    listener_host="unknown",
    listener_loopback=False,
    api_key=False,
    oidc_bearer=False,
    oidc_browser=False,
    snowflake_oauth=False,
    scim_bearer=False,
    saml=False,
    trusted_proxy=False,
    anonymous_allowed=False,
)


_AUTH_POSTURE: AuthPosture = _EMPTY_AUTH_POSTURE


def apply_auth_posture(posture: AuthPosture) -> None:
    """Store the derived posture and project it into the runtime-status dict."""
    global _AUTH_POSTURE
    _AUTH_POSTURE = posture
    _AUTH_RUNTIME_STATUS.clear()
    _AUTH_RUNTIME_STATUS.update(posture.runtime_status())


def get_auth_posture() -> AuthPosture:
    """Return the last-applied derived auth posture (the single source of truth)."""
    return _AUTH_POSTURE


def get_auth_runtime_status() -> dict[str, object]:
    """Return the configured auth modes for UI and operator surfaces."""
    return dict(_AUTH_RUNTIME_STATUS)
