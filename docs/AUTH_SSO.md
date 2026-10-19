# Single sign-on (OIDC) — 5-minute setup

Turn on **"Sign in with Google"** (or any OIDC issuer) for the agent-bom
dashboard without hand-wiring environment variables. The guided command
collects your IdP details, validates the issuer, and emits the exact
`AGENT_BOM_OIDC_*` configuration.

This is the onboarding path for the browser auth-code + PKCE SSO mechanism
documented in
[`DEPLOY_PLATFORM.md`](#supported-authentication-paths-single-matrix) — it does
not change how tokens are validated. Reverse-proxy SSO
(`AGENT_BOM_TRUST_PROXY_AUTH=1`) remains the preferred posture for larger fleets;
this path is the fastest for a solo self-hoster.

---

Public health, documentation, and login routes exempt only their declared HTTP
methods from authentication (HEAD follows GET). An added method on the same
URL fails closed through normal authentication; login/logout handlers still
validate their own credentials, state, and CSRF requirements. The operation
inventory lives in `api/route_policy.py` and is checked against mounted routes.

## The command

```bash
agent-bom auth setup-oidc
```

Interactive on a terminal — it prompts for the provider, client ID, optional
runtime secret-file path, and your deployment's base URL. Fully flag-driven for
automation:

```bash
agent-bom auth setup-oidc \
  --non-interactive \
  --provider google \
  --client-id  <client-id>.apps.googleusercontent.com \
  --client-secret-file /run/agent-bom/oidc/client_secret \
  --base-url https://abom.example.com \
  --write                      # write deploy/secrets/oidc.env (default path)
```

It prints the provider-side steps, a copy-paste non-secret env block, and (with
`--write` or an interactive confirmation) saves the block to
`deploy/secrets/oidc.env`. The wizard never reads, prints, or writes a client
secret value; confidential clients reference an operator-managed mounted file.

For Compose, provision the secret as `deploy/secrets/oidc/client_secret` before
starting the stack. The shipped platform and full-stack profiles mount that
dedicated directory read-only and load `oidc.env` automatically when present.

### Migrating automation

The setup command does not accept a `--client-secret` option because process
arguments and shell history can expose secret values. Update automation to use
an absolute, normalized runtime file reference:

```bash
agent-bom auth setup-oidc ... \
  --client-secret-file /run/agent-bom/oidc/client_secret
```

The wizard emits `AGENT_BOM_OIDC_CLIENT_SECRET_FILE`; it never reads the
referenced file or emits its contents.

> The redirect URI is always derived as `<base-url>/v1/auth/oidc/callback` — the
> dashboard's OIDC callback route. It must be allowlisted at the IdP **exactly**.

---

## Sign in with Google

1. **Google Cloud Console → APIs & Services → Credentials.**
2. **Create Credentials → OAuth client ID → Application type: Web application.**
3. Add an **Authorized redirect URI**, exactly:
   `https://<your-host>/v1/auth/oidc/callback`
4. **Create**, then copy the **Client ID**. Store the **Client secret** in your
   secret manager and mount it read-only at a runtime path such as
   `/run/agent-bom/oidc/client_secret`.
5. Run the command with the client ID and runtime secret-file path (issuer is
   preset to `https://accounts.google.com`):

   ```bash
   agent-bom auth setup-oidc --provider google \
     --client-id <id>.apps.googleusercontent.com \
     --client-secret-file /run/agent-bom/oidc/client_secret \
     --base-url https://<your-host> --write
   ```

6. Load the emitted env on the API process and restart, then open the dashboard
   `/login` → **Sign in with SSO**.

Resulting env block:

```dotenv
AGENT_BOM_OIDC_ISSUER=https://accounts.google.com
AGENT_BOM_OIDC_CLIENT_ID=<id>.apps.googleusercontent.com
AGENT_BOM_OIDC_CLIENT_SECRET_FILE=/run/agent-bom/oidc/client_secret
AGENT_BOM_OIDC_REDIRECT_URI=https://<your-host>/v1/auth/oidc/callback
AGENT_BOM_OIDC_AUDIENCE=<id>.apps.googleusercontent.com
AGENT_BOM_OIDC_ALLOW_DEFAULT_TENANT=1
```

- **`AGENT_BOM_OIDC_AUDIENCE`** defaults to the client ID — the browser ID
  token's `aud` claim is the OAuth client ID.
- **`AGENT_BOM_OIDC_ALLOW_DEFAULT_TENANT=1`** is emitted for a single-tenant
  self-host so SSO users resolve to the default tenant. Google emits no tenant
  claim, and multi-tenant enforcement is fail-closed by default. Configure a
  `--tenant-claim` instead when running multi-tenant (see below).

### Loading the env

- **Docker Compose:** `docker-compose.platform.yml` and
  `docker-compose.fullstack.yml` load `deploy/secrets/oidc.env` when it exists
  and mount `deploy/secrets/oidc/` read-only at `/run/agent-bom/oidc`. Write the
  client secret to `deploy/secrets/oidc/client_secret`; the generated env file
  contains only its runtime path. The dedicated directory is gitignored.
- **systemd / bare process:** export the variables into the API process
  environment (an `EnvironmentFile=` works with the same dotenv file) and set
  `AGENT_BOM_OIDC_CLIENT_SECRET_FILE` to a protected file readable by the API
  service account.

---

## Generic OIDC (Okta, Entra ID, Auth0, Keycloak)

Use `--provider generic` and pass the issuer explicitly. The `.well-known/openid-configuration`
discovery document under the issuer is what the wizard validates.

| IdP        | Issuer example                                             |
|------------|-------------------------------------------------------------|
| Okta       | `https://<org>.okta.com`                                    |
| Entra ID   | `https://login.microsoftonline.com/<tenant-id>/v2.0`        |
| Auth0      | `https://<tenant>.us.auth0.com/`                            |
| Keycloak   | `https://<host>/realms/<realm>`                             |

```bash
agent-bom auth setup-oidc --provider generic \
  --issuer https://<org>.okta.com \
  --client-id <client-id> \
  --client-secret-file /run/agent-bom/oidc/client_secret \
  --base-url https://<your-host> \
  --role-claim groups \
  --tenant-claim org_id \
  --write
```

- A **PKCE public client** (no secret) is supported — omit
  `--client-secret-file`.
- `--role-claim` maps a JWT claim to an agent-bom role (default `agent_bom_role`;
  `roles`/`groups`/`permissions` arrays are also honored).
- `--tenant-claim` maps a JWT claim to a tenant. When set, the wizard does **not**
  emit `AGENT_BOM_OIDC_ALLOW_DEFAULT_TENANT` — tenancy comes from the claim.

If the issuer is unreachable when you run the command (offline/air-gapped), the
wizard prints a warning and still emits a valid env block — verify the issuer URL
by hand.

---

## Reference

- Auth mechanisms and the browser SSO route: [`DEPLOY_PLATFORM.md`](#supported-authentication-paths-single-matrix)
- Claim mapping and tenant enforcement: `src/agent_bom/api/oidc.py`
- Compose secrets layout: [`../deploy/secrets/README.md`](../deploy/secrets/README.md)

## Inspect effective route permissions

Use an authenticated administrator session to request `GET /v1/auth/scopes`.
The response lists method, resource prefix, scope action and minimum role for
scoped API operations; use it when assigning narrowly scoped service keys.

The catalog and middleware share `api/route_policy.py`. Rules match path
segments, with the most specific subpath winning; `HEAD` inherits `GET`.
Unclassified protected operations return `403` after authentication, including
for administrators, static keys, OIDC/proxy sessions and explicitly enabled
anonymous access. Empty or wildcard key scopes apply only to classified
operations. Custom routes must add an explicit operation policy before use. Authentication remains
required unless the deployment explicitly enables the documented local/demo
mode; missing or invalid credentials do not gain access through these rules.
Route dependencies may impose additional resource or tenant checks.
The catalog covers scoped rules, not a complete list of every API operation.

## Browser account and sign-out

Open **Account menu → Profile & settings** to inspect the current identity,
authentication method, role and authorized scope. API-key sessions identify a
key, not a person. Identity and role changes remain with the configured identity
provider or administrator. Settings links expose the existing Connections,
Access & keys, Audit history and Control plane security surfaces according to
server-reported capabilities; they do not create additional tenant memberships.
Appearance supports light, dark and system preferences saved in the browser.

Browser-cookie verification reuses one derived signing key per API process.
The configured secret is read on every verification, so rotating the environment
value or mounted secret file invalidates cookies signed with the previous key;
restart processes to apply changes to their inherited environment. A configured
secret file that becomes unreadable does not fall back to the cached key. This
cache does not retain authentication decisions: expiry, revocation, current
backing-key permissions, tenant policy and CSRF checks still apply. Malformed
cookies fail closed before signing-key derivation.

**Sign out** revokes the local browser session and clears in-memory response
caches. The UI locks immediately, rejects late authentication responses and
propagates sign-out to other same-origin tabs. A failed revocation remains an
unconfirmed sign-out with a retry action; it is not reported as server success.
Loopback dashboard navigation respects the sign-out cookie instead of silently
issuing a new development session. **Continue to sign in** explicitly resumes
authentication. Logout does not revoke the API key itself or end an upstream
identity-provider/reverse-proxy session. An explicitly unauthenticated server
cannot be secured by a browser sign-out action.

After explicit logout, the loopback `/v1/auth/dev-session` exchange returns
`409` until an explicit browser resume supplies `X-Agent-Bom-Session-Resume: true`.
The existing loopback-origin restriction still applies; this header records intent
and does not grant access to a remotely bound or explicitly authenticated server.

## Authentication Contract

`agent-bom api` and `agent-bom serve` support four runtime postures:

1. Loopback development
   - localhost binds are allowed without remote auth
2. API key enforcement
   - non-loopback binds require `AGENT_BOM_API_KEY` or stored API keys
   - set `AGENT_BOM_API_KEY_DEFAULT_TTL_SECONDS` and `AGENT_BOM_API_KEY_MAX_TTL_SECONDS`
     to enforce rotation windows on stored keys
   - rotate stored keys with `POST /v1/auth/keys/{key_id}/rotate`
3. OIDC bearer enforcement
   - set `AGENT_BOM_OIDC_ISSUER`, or use `AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON` for tenant-bound issuers
   - set `AGENT_BOM_OIDC_AUDIENCE`
   - map roles with `AGENT_BOM_OIDC_ROLE_CLAIM`
   - map tenants with `AGENT_BOM_OIDC_TENANT_CLAIM`
   - missing tenant claims fail closed by default
   - opt into single-tenant default mode only with `AGENT_BOM_OIDC_ALLOW_DEFAULT_TENANT=1`
   - optionally set `AGENT_BOM_OIDC_REQUIRED_NONCE` when your IdP flow includes a nonce claim
4. SCIM lifecycle provisioning
   - set `AGENT_BOM_SCIM_BEARER_TOKEN` to enable `/scim/v2/Users`, `/scim/v2/Groups`, and `/scim/v2/ServiceProviderConfig`
   - set `AGENT_BOM_SCIM_TENANT_ID` to bind all inbound SCIM lifecycle writes to one tenant; tenant IDs supplied by the IdP payload are ignored
   - set `AGENT_BOM_SCIM_BASE_PATH` before API startup if your IdP requires a different SCIM path
   - use PostgreSQL or Supabase for clustered, multi-node, or EKS deployments; SQLite is only for single-node pilots
   - SCIM traffic uses the dedicated SCIM bearer token only and does not accept dashboard sessions or general API keys

Rate limiting also follows an explicit fail-closed contract for scaled control planes:

- single-process / single-replica API: in-memory limiter is allowed
- multi-replica API or `AGENT_BOM_REQUIRE_SHARED_RATE_LIMIT=1`: PostgreSQL-backed shared limiter is required
- if shared rate limiting is required and `AGENT_BOM_POSTGRES_URL` is absent or broken, API startup now fails instead of silently falling back to process-local state
- WebSocket handshake attempts consume a peer-scoped budget before authentication work begins; an exhausted budget or unavailable limiter closes the connection before the first-message credential wait

API-local filesystem scans follow the same pilot-vs-control-plane split:

- default posture: API-local filesystem scans are disabled unless `AGENT_BOM_API_LOCAL_PATH_SCANS=enabled` is set
- workstation pilot: set `AGENT_BOM_API_LOCAL_PATH_SCANS=enabled`; relative paths resolve under the API process home unless `AGENT_BOM_API_SCAN_ROOT` is set
- EKS/shared control plane: keep `AGENT_BOM_API_LOCAL_PATH_SCANS=disabled` and collect filesystem evidence through endpoint agents or mounted tenant workspaces
- explicit single-tenant enablement: set `AGENT_BOM_API_SCAN_ROOT` to a mounted tenant workspace; the API still rejects absolute paths, traversal, symlink escapes, missing paths, and foreign-owned paths unless explicitly overridden

Implementation source: `src/agent_bom/api/middleware.py`, `src/agent_bom/api/oidc.py`

## Supported authentication paths (single matrix)

`agent-bom` has one RBAC/tenant model; every path below resolves into it. mTLS is a **transport** posture (see [proxy-to-control-plane mTLS](#proxy-to-control-plane-mtls-posture)), not a user identity, and LDAP directory bind is not supported.

| Path | Configure with | Surface | Counts toward the boot-gate / `auth_configured`? |
| --- | --- | --- | --- |
| API key (M2M) | `AGENT_BOM_API_KEY` / `AGENT_BOM_API_KEYS` | CLI · API · MCP | Yes |
| OIDC JWT (bearer) | `AGENT_BOM_OIDC_ISSUER` or `AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON` | API · UI (bearer) | Yes |
| OIDC browser SSO (auth-code + PKCE) | Issuer + `AGENT_BOM_OIDC_CLIENT_ID` + `AGENT_BOM_OIDC_REDIRECT_URI` (optional secret/scopes) | Dashboard `/login` → `/v1/auth/oidc/login` | Yes (signals `oidc_browser` in auth runtime) |
| Snowflake OAuth sign-in (auth-code + PKCE) | `AGENT_BOM_SNOWFLAKE_OAUTH_ACCOUNT_URL` + `AGENT_BOM_SNOWFLAKE_OAUTH_CLIENT_ID` + `AGENT_BOM_SNOWFLAKE_OAUTH_REDIRECT_URI` + `AGENT_BOM_SNOWFLAKE_OAUTH_CLIENT_SECRET` | Dashboard `/login` → `/v1/auth/snowflake/login` | Yes (signals `snowflake_oauth` in auth runtime) |
| SAML SSO (browser) | `AGENT_BOM_SAML_IDP_*` + `AGENT_BOM_SAML_SP_*` | UI (mints a short-lived session API key) | Yes |
| SCIM bearer (provisioning) | `AGENT_BOM_SCIM_BEARER_TOKEN` | `/scim/v2/*` only | Yes |
| Trusted reverse proxy | `AGENT_BOM_TRUST_PROXY_AUTH=1` | UI · API | Yes (upstream proxy is the authority; preferred when present) |
| Browser session cookie | Minted server-side after OIDC/SAML/proxy login | UI | Derived — not a standalone configured path |
| mTLS (client cert) | `AGENT_BOM_TLS_REQUIRE_CLIENT_CERT=1` | Transport | No — transport posture, not RBAC identity |

Keys configured through `AGENT_BOM_API_KEYS` (including its `_FILE` source) are
seeded into the key store at startup. The runtime WebSocket streams
(`/ws/proxy/metrics` and `/ws/proxy/alerts`) use that store's current identity,
role, scope, and lifecycle checks. Revoked, expired, or rotated-out keys fail
closed on reconnect, even while their original configuration remains present.
Setting the environment variable after startup does not bypass store enrollment.
Remove retired credentials from deployment configuration as part of rotation;
an in-memory store does not retain revocation across process restarts.

A SAML-only deployment is a valid, fail-closed posture: browser users authenticate against the IdP and receive a short-lived session API key, while anonymous requests are still rejected (401) by the API-key middleware, which stays installed whenever any auth path is configured.

**Dashboard OIDC auth-code + PKCE:** when the control plane has an OIDC issuer plus a confidential or public client (`AGENT_BOM_OIDC_CLIENT_ID`, `AGENT_BOM_OIDC_REDIRECT_URI`, optional file-first `AGENT_BOM_OIDC_CLIENT_SECRET_FILE` / legacy `AGENT_BOM_OIDC_CLIENT_SECRET` / `AGENT_BOM_OIDC_SCOPES`), the dashboard shows **Sign in with SSO**. That CTA navigates same-origin to `GET /v1/auth/oidc/login`, completes the IdP authorize + callback with PKCE S256, and mints the usual httpOnly browser session + CSRF cookies. Role and tenant claims map through the same OIDC claim contract as bearer JWT verification. Reverse-proxy SSO remains preferred when `AGENT_BOM_TRUST_PROXY_AUTH=1` is set. Laptop-to-gateway MCP PKCE is a separate later surface — not this dashboard path. mTLS remains transport only and never substitutes for user identity. For a guided 5-minute "Sign in with Google" / OIDC walkthrough that emits this configuration for you, run `agent-bom auth setup-oidc` (see [`AUTH_SSO.md`](AUTH_SSO.md)).

**Dashboard Snowflake OAuth sign-in:** Snowflake exposes a non-standard OAuth 2.0 authorization server — no OIDC discovery document, no JWKS, and no `userinfo` endpoint — so it uses a dedicated path rather than the generic OIDC flow. Configure it with the account's OAuth security integration (`AGENT_BOM_SNOWFLAKE_OAUTH_ACCOUNT_URL` = your `https://<org>-<account>.snowflakecomputing.com` URL, `AGENT_BOM_SNOWFLAKE_OAUTH_CLIENT_ID`, `AGENT_BOM_SNOWFLAKE_OAUTH_CLIENT_SECRET` [file-first via the secrets loader, write-only], `AGENT_BOM_SNOWFLAKE_OAUTH_REDIRECT_URI` = `https://cp.example/v1/auth/snowflake/callback`, and — if you want a role-scoped consent — `AGENT_BOM_SNOWFLAKE_OAUTH_SCOPE`). The dashboard then shows **Sign in with Snowflake**, which navigates same-origin to `GET /v1/auth/snowflake/login`, drives Snowflake's `/oauth/authorize` + `/oauth/token-request` authorization-code flow with PKCE S256, and mints the usual httpOnly session + CSRF cookies. Because Snowflake has no ID token, identity is the `username` the token endpoint returns (a missing username fails closed); role defaults to the least-privilege `AGENT_BOM_SNOWFLAKE_OAUTH_DEFAULT_ROLE` (`viewer`) and is only elevated by an explicit SCIM mapping for that user. Endpoint shapes verified against Snowflake's [Configure Snowflake OAuth for custom clients](https://docs.snowflake.com/en/user-guide/oauth-custom) docs.

**Tracing:** every API response includes `X-Request-ID`, `X-Trace-ID`, `X-Span-ID`, and W3C `traceparent`. If your ingress or collector already sends `traceparent`, `tracestate`, or bounded W3C `baggage`, `agent-bom` preserves the upstream trace context and continues the chain. Authenticated `GET /v1/system/health` reports the current tracing contract (`w3c_trace_context`, `w3c_tracestate`, `w3c_baggage`) plus OTLP export state so operators can confirm whether tracing is merely available or actively exported. Set `AGENT_BOM_OTEL_TRACES_ENDPOINT` to export API request spans over OTLP/HTTP, and use `AGENT_BOM_OTEL_TRACES_HEADERS` for collector auth headers when needed.

For OIDC-backed enterprise deployments, keep tenant scoping explicit in the token contract:

```bash
export AGENT_BOM_OIDC_ISSUER="https://idp.example.com"
export AGENT_BOM_OIDC_AUDIENCE="agent-bom"
export AGENT_BOM_OIDC_ROLE_CLAIM="agent_bom_role"
export AGENT_BOM_OIDC_TENANT_CLAIM="tenant_id"      # or a custom claim like org_slug
# export AGENT_BOM_OIDC_ALLOW_DEFAULT_TENANT=1      # only for explicit single-tenant compatibility mode
# export AGENT_BOM_OIDC_REQUIRED_NONCE="replace-me"  # optional when your IdP flow emits nonce
# Dashboard SSO (auth-code + PKCE) — in addition to bearer verification:
# export AGENT_BOM_OIDC_CLIENT_ID="agent-bom-dashboard"
# export AGENT_BOM_OIDC_REDIRECT_URI="https://cp.example/v1/auth/oidc/callback"
# export AGENT_BOM_OIDC_CLIENT_SECRET_FILE=/run/agent-bom/oidc/client_secret  # optional, file-first
# export AGENT_BOM_OIDC_SCOPES="openid profile email"
```

That keeps API roles and tenant boundaries aligned with the upstream identity provider. Missing tenant claims now fail closed by default instead of silently falling back to a shared tenant; `AGENT_BOM_OIDC_ALLOW_DEFAULT_TENANT=1` is the explicit compatibility escape hatch for single-tenant deployments.

For tenant-bound issuers, configure one issuer per tenant and do not also set `AGENT_BOM_OIDC_ISSUER`:

```bash
export AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON='{
  "tenant-alpha": {
    "issuer": "https://alpha.okta.example",
    "audience": "agent-bom",
    "tenant_claim": "tenant_id",
    "require_tenant_claim": true
  },
  "tenant-beta": {
    "issuer": "https://beta.okta.example",
    "audience": "agent-bom",
    "tenant_claim": "tenant_id",
    "require_tenant_claim": true
  }
}'
```

At startup, `agent-bom` treats `AGENT_BOM_OIDC_ISSUER` and `AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON` as mutually exclusive. Mixed configuration now fails closed instead of silently choosing one mode.

For SCIM-backed enterprise identity provisioning, use the dedicated SCIM token and tenant binding:

```bash
export AGENT_BOM_SCIM_BEARER_TOKEN="replace-with-idp-scim-token"
export AGENT_BOM_SCIM_TENANT_ID="tenant-alpha"
# export AGENT_BOM_SCIM_BASE_PATH="/scim/v2"
```

SCIM lifecycle traffic is available under `/scim/v2/Users`, `/scim/v2/Groups`, `/scim/v2/ServiceProviderConfig`, `/scim/v2/Schemas`, and `/scim/v2/ResourceTypes`. These routes require `AGENT_BOM_SCIM_BEARER_TOKEN`; dashboard sessions and general API keys are not accepted. The tenant is always taken from `AGENT_BOM_SCIM_TENANT_ID`, so tenant fields in the IdP payload cannot steer writes into another tenant.

Provisioned SCIM users carry Agent BOM role and membership metadata. Set
`AGENT_BOM_SCIM_ROLE_ATTRIBUTE` when the IdP sends roles under a custom
attribute; otherwise users default to `AGENT_BOM_SCIM_DEFAULT_ROLE` (`viewer`).
Accepted role values are `admin`, `analyst`, and `viewer` (`contributor` is
normalized to `analyst`). SCIM remains the lifecycle store: deleting or
deactivating a SCIM user updates provisioned identity state and audit evidence,
while runtime API-key, OIDC, SAML, and reverse-proxy sessions are revoked by
their own upstream auth path.

Compatibility coverage is maintained for common IdP payload shapes:

- Okta user/group lifecycle payloads with `externalId`, `emails`, `groups`, and active-state patches
- Microsoft Entra ID SCIM replace patches that send a value object instead of a single path
- Google Cloud Identity payloads that rely on `name.formatted` when `displayName` is absent

Check `/v1/auth/policy` or `/v1/auth/scim/config` for the non-secret
`verified_idp_templates` posture before procurement or IdP rollout reviews.

For PostgreSQL-backed deployments, `agent-bom` now also pushes the authenticated tenant into the database session (`app.tenant_id`) so Postgres row-level security can enforce the same tenant boundary for fleet and schedule data. Internal scheduler work uses an explicit trusted bypass rather than silently reading across tenants.

For horizontally scaled control-plane APIs, shared rate limiting is mandatory. `agent-bom` now fails closed when `AGENT_BOM_CONTROL_PLANE_REPLICAS > 1` (or `AGENT_BOM_REQUIRE_SHARED_RATE_LIMIT=1`) and no PostgreSQL-backed limiter is configured via `AGENT_BOM_POSTGRES_URL`.

## Delegation source lifecycle

Issue a delegation with `POST /v1/identities/{identity_id}/delegations`, then
check it with `POST /v1/delegations/verify` before using its capabilities.
The signed token and response record `source_identity_id`. The source must be
in the authenticated tenant, active (or within rotation overlap), unexpired,
and permitted to use every requested tool. Token expiry is capped by source
expiry. Empty source tool allowlists and `*` retain their existing meaning:
any tool that the runtime policy permits.

Verification and propagation reload that exact source identity. Revocation,
expiry, ended rotation overlap, or a narrower tool allowlist invalidates both
the original token and descendants that exceed current authority. Missing
source records and storage errors fail closed; verification returns
`valid: false`, and no child token is returned. No source lookup uses agent
names or another tenant as a fallback. Previously issued tokens without a
signed source identity must be reissued; cryptographic verification alone
cannot establish current identity authority.

These endpoints retain their existing operator role/scope requirements.
A delegatee name and a caller-supplied chain are metadata, not proof that a
receiver authenticated as that agent. Receivers still need their own
authentication and runtime policy enforcement. Use shared Postgres identity
storage and the dedicated delegation signing key across replicas; SQLite
restart coverage does not establish distributed failover qualification.

JIT grant reads, writes, approval, denial, and revocation require an explicit
tenant in the service/store API. Conditional-access policy reads, writes and
status changes have the same contract. Unknown or foreign resource IDs cannot
be mutated, and a write cannot transfer an existing ID to another tenant.
SQLite enforces this in the upsert itself; Postgres retains both the SQL tenant
predicate and FORCE RLS. In-memory reads return copies so changing a fetched
grant or a policy condition cannot change authorization until a validated
write succeeds. Integrations
calling these Python methods must pass `tenant_id` from verified context.

## Dashboard sign-in route

The browser UI exposes a dedicated sign-in surface at `/login`. Unauthenticated
users are redirected there with a `returnTo` query parameter so they can resume
the page they requested after establishing a browser session — via reverse-proxy
SSO, first-party OIDC auth-code/PKCE (**Sign in with SSO** → `/v1/auth/oidc/login`),
or API-key exchange.

First command for a pilot operator:

```text
open https://<control-plane-host>/login
```

After sign-in, open **Connections** (`/connections`) to add a read-only cloud
account, then launch or schedule a scan from the same dashboard.

## MCP OIDC discovery shim

When MCP OAuth clients require `/.well-known/openid-configuration` at your
gateway hostname but the buyer IdP only exposes manually configured endpoints,
enable the read-only discovery shim on the gateway:

```bash
export AGENT_BOM_OIDC_DISCOVERY_SHIM_JSON='{
  "issuer": "https://mcp-auth.example.internal",
  "authorization_endpoint": "https://idp.example.com/oauth2/v1/authorize",
  "token_endpoint": "https://idp.example.com/oauth2/v1/token",
  "jwks_uri": "https://idp.example.com/oauth2/v1/keys"
}'
```

The shim publishes public metadata only; tokens still come from the upstream
IdP. Embedded gateway OAuth issuance is unavailable until trusted client
authorization is implemented. `--enable-oauth-as` and
`AGENT_BOM_GATEWAY_ENABLE_OAUTH_AS` now fail startup; remove the setting and
configure bearer or API-key authentication. The gateway does not accept tokens
from the former embedded issuer. Existing external OIDC/JWKS identity validation
and the read-only discovery shim remain available.

See [`docs/design/OIDC_DISCOVERY_SHIM.md`](design/OIDC_DISCOVERY_SHIM.md) and
`deploy/helm/agent-bom/examples/oidc-discovery-shim-values.yaml` for architecture,
Helm overlay, and contract tests.

## Proxy-to-control-plane mTLS posture

The recommended production pattern is delegated mTLS: terminate TLS and verify
proxy or gateway client certificates at the ingress, Envoy sidecar, or service
mesh boundary, then keep trusted-proxy header attestation enabled so direct
client-supplied identity headers remain ignored. This keeps certificate
lifecycle, rotation, and policy in the mesh or ingress layer.

Declare the operator posture with:

```bash
AGENT_BOM_PROXY_CONTROL_PLANE_MTLS_MODE=delegated
AGENT_BOM_PROXY_CONTROL_PLANE_MTLS_PROVIDER=istio
AGENT_BOM_PROXY_CONTROL_PLANE_MTLS_CLIENT_CA_REF=secret/agent-bom/proxy-client-ca
AGENT_BOM_PROXY_CONTROL_PLANE_MTLS_EVIDENCE_REF=deploy/helm/agent-bom/templates/controlplane-istio-peer-authentication.yaml
AGENT_BOM_PROXY_CONTROL_PLANE_MTLS_CERT_HEADER=x-forwarded-client-cert
AGENT_BOM_TRUST_PROXY_AUTH=1
AGENT_BOM_TRUST_PROXY_AUTH_SECRET=<32+ byte shared attestation secret>
AGENT_BOM_TRUST_PROXY_AUTH_ISSUER=edge-envoy
AGENT_BOM_TRUSTED_PROXY_HOPS=1
AGENT_BOM_TRUSTED_PROXY_CIDRS=10.0.10.0/24,10.0.11.0/24
```

Set `AGENT_BOM_TRUSTED_PROXY_HOPS` to the exact number of trusted forwarding
hops and `AGENT_BOM_TRUSTED_PROXY_CIDRS` to the API-facing proxy subnet CIDRs.
Both are required before auth rate limits use `X-Forwarded-For`; direct peers
outside those networks and short, malformed, or oversized chains fall back to
the transport peer. `/v1/auth/policy` reports the effective client-identity
source and any incomplete or invalid topology warning.

`GET /v1/auth/policy` exposes `proxy_control_plane_mtls` with one of three
honest states:

- `disabled` — no mTLS posture has been declared.
- `needs_evidence` — delegated mTLS is declared, but client-CA evidence,
  evidence reference, or trusted-proxy issuer pinning is incomplete.
- `ok` — delegated mTLS is declared, client-CA evidence is referenced, and
  trusted-proxy auth is issuer-pinned.

For NGINX, set `ssl_verify_client on;`, trust the proxy client CA with
`ssl_client_certificate`, and forward only sanitized identity headers from the
verified location block. For Envoy, use `DownstreamTlsContext` with
`require_client_certificate: true` and forward `x-forwarded-client-cert` only
after SAN/URI validation. For Istio, use `PeerAuthentication` `STRICT` plus an
`AuthorizationPolicy` that limits caller identities to the proxy/gateway service
accounts. In all three patterns, `AGENT_BOM_TRUST_PROXY_AUTH_SECRET` and
`AGENT_BOM_TRUST_PROXY_AUTH_ISSUER` remain the application-level guard against
spoofed `X-Agent-Bom-*` headers.

For non-mesh deployments such as a single VM, air-gapped host, or bare Docker
deployment, `agent-bom` also supports an app-native mTLS fallback through
uvicorn TLS settings:

```bash
AGENT_BOM_PROXY_CONTROL_PLANE_MTLS_MODE=app_native
AGENT_BOM_TLS_CERT_FILE=/etc/agent-bom/tls/tls.crt
AGENT_BOM_TLS_KEY_FILE=/etc/agent-bom/tls/tls.key
AGENT_BOM_TLS_CLIENT_CA_FILE=/etc/agent-bom/tls/client-ca.crt
AGENT_BOM_TLS_REQUIRE_CLIENT_CERT=1
```

`agent-bom serve` and `agent-bom api` pass these files to uvicorn and require
client certificates when `AGENT_BOM_TLS_REQUIRE_CLIENT_CERT=1` is set.
`GET /v1/auth/policy` reports this as
`proxy_control_plane_mtls.mtls_mode=app_native`.

Direct-hop rule: if the FastAPI listener is behind ingress or a sidecar, bind
it to `127.0.0.1`, a Unix socket, or a Kubernetes NetworkPolicy path that only
allows the sidecar or ingress to reach the pod. In production or clustered
control planes, `agent-bom` fails closed when a non-loopback listener is exposed
without either trusted-proxy attestation or app-native mTLS.

API-local filesystem scan endpoints are meant for workstation pilots. In EKS
and other shared control planes they are disabled by default; keep
`AGENT_BOM_API_LOCAL_PATH_SCANS=disabled` and collect filesystem evidence
through endpoint agents or mounted tenant workspaces. If a single-tenant
deployment must enable API-local scans, set
`AGENT_BOM_API_LOCAL_PATH_SCANS=enabled` and `AGENT_BOM_API_SCAN_ROOT` to the
tenant workspace mount; paths are still relative-only, resolved through
symlinks, confined to that root, and rejected when owned outside the API
process unless `AGENT_BOM_API_SCAN_ALLOW_FOREIGN_OWNER=1` is explicitly set.

Ambient host MCP discovery is a separate, broader boundary: it reads the API
process's own MCP configuration, not the browser's workstation and not only
the configured scan-root mount. The request flag `discover_host=true` grants
no permission by itself. On an exclusively assigned single-tenant host, an
operator must enable local scans and set
`AGENT_BOM_API_HOST_DISCOVERY_TENANT` to that tenant's exact ID. Other tenants
are denied. Leave this variable unset on shared control planes. The gate is
checked both before accepting API/source runs and again by the worker;
revoking permission also blocks queued jobs before discovery. Rejections are
fail-closed and do not include filesystem paths or other tenant identifiers.
`GET /v1/agents` (and its mesh/detail routes) applies the same gate: only
the bound tenant sees the API host's own AI clients, and in demo mode only the
showcase tenant sees the curated demo inventory. Every other tenant gets its
scanned-estate agents (`scope: "scanned_estate"`), the same population
`/v1/inventory` returns. These reads never write: live discovery is merged into
the response in memory and is not persisted as MCP observations.

## Role and operation policy

The [route policy](../src/agent_bom/api/route_policy.py) is the owning catalog
for minimum roles and scopes. Specific path segments take precedence, HEAD
uses GET policy, and unclassified protected operations fail closed after
authentication. Public access is an explicit method/path contract.

| Operation | Minimum role | Scope |
|---|---|---|
| `GET /v1/auth/keys` | `admin` | `auth.keys:read` |
| `POST /v1/fleet/sync` | `admin` | `fleet:write` |
| `POST /v1/findings/false-positive` | `analyst` | `finding:write` |
| `POST /v1/results/push` | `analyst` | `scan:write` |

These examples do not replace the complete catalog or tenant checks. See
[tenant resolution](TENANT_RESOLUTION.md) and the [OpenAPI contract](openapi/README.md).
