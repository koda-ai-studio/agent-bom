# Hosted deployment runbook

| Lane | Who runs it | What it is |
|---|---|---|
| [Public demo](https://koda-ai-studio.github.io/agent-bom/demo/) | This project | A read-only static export on GitHub Pages with labelled sample data. |
| [Self-host](#self-host-your-own-instance) | You | An authenticated instance on your infrastructure with persistent Postgres and real connections. |
| [Snowflake Native App](#snowflake-native-app-lane) | You | agent-bom inside your Snowflake account. |

## Public demo (GitHub Pages)

Open the [read-only demo](https://koda-ai-studio.github.io/agent-bom/demo/).
It serves bundled sample JSON and has no live scanner API, cloud credentials,
sign-in, or writable connections. To inspect your own environment, use the
[quick start](https://koda-ai-studio.github.io/agent-bom/getting-started/quickstart/)
or the self-hosted deployment below.

[`.github/workflows/docs-build.yml`](../.github/workflows/docs-build.yml) builds
the static dashboard, generates sample fixtures, checks for accidental data
exposure, and runs browser checks with no API behind the site.
[`.github/workflows/docs.yml`](../.github/workflows/docs.yml) deploys the verified
site to GitHub Pages. The public demo is no longer deployed to Cloud Run or a VM.
Release-image smoke tests and customer deployment checks remain separate from
this static sample journey.

## Self-host: your own instance

This lane is for an instance **you** operate: a gated deployment that holds real
connections and state, for a customer-0 POC, an internal pilot, or your own
production use. It is not how the public demo above runs, and it needs a
persistent Postgres.

Throughout this section, `agent-bom.example.com` stands in for your own
hostname.

### Host sizing

One small CPU-only host is enough to start:

- 4 vCPU / 8-16 GB RAM
- Ubuntu LTS or equivalent
- A region close to you and your first users
- Inbound `443` from your trusted edge only; no inbound SSH/admin port. Use your
  cloud's session-manager equivalent for operator access.

### Stand-up

1. Point DNS for your hostname at the host.
2. Allow inbound `443` only from the trusted edge (for example, your CDN's
   published proxy CIDRs).
3. Install Docker, Compose, and a TLS terminator (Caddy below, or a managed load
   balancer).
4. Deploy `deploy/docker-compose.platform.yml`.
5. Terminate HTTPS at the front door. Do not expose plain HTTP.
6. Set production secrets:
   - `AGENT_BOM_AUDIT_HMAC_KEY`
   - `AGENT_BOM_BROWSER_SESSION_SIGNING_KEY`
   - `AGENT_BOM_CONNECTIONS_KEY`
   - the initial admin API key or OIDC reverse-proxy session settings
7. Keep `AGENT_BOM_ALLOW_UNAUTHENTICATED_API` unset.
8. Mint one admin tenant/key for the first account.
9. Connect read-only AWS, Azure, GCP, and Snowflake targets.
10. Run the first scan and verify findings, graph, posture, and exports.

This gives users the full product experience: sign in, connect read-only, scan,
inspect graph/blast radius, and export evidence.

### DNS

Create one record per lane you serve, pointing at your host:

| Record | Purpose |
|---|---|
| `agent-bom.example.com` | the instance UI + API |

If you front the host with a proxying CDN, keep proxy mode and TLS mode
consistent:

- **DNS-only + Caddy** — simplest. Caddy terminates Let's Encrypt directly.
- **Proxied + Caddy** — set the CDN's SSL mode to `Full (strict)` and let Caddy
  still hold a valid origin certificate.

Do not point the apex/root domain at the instance unless it is also serving your
product site.

### Minimal host setup

Generate local secrets on the host:

```bash
cp .env.example .env

export NEXT_PUBLIC_API_URL="https://agent-bom.example.com"
export CORS_ORIGINS="https://agent-bom.example.com,http://ui:3000"
export AGENT_BOM_SESSION_COOKIE_SECURE=1

# All secrets are file mounts only — never .env / compose env.
python scripts/deploy/hosted_poc_preflight.py --write-secret --skip-compose
# Or write files manually — see deploy/secrets/README.md
```

Start the platform:

```bash
docker compose \
  -f deploy/docker-compose.platform.yml \
  -f deploy/docker-compose.hosted-poc.yml \
  up -d --build

docker compose \
  -f deploy/docker-compose.platform.yml \
  -f deploy/docker-compose.hosted-poc.yml \
  ps
```

`up` runs a one-shot `migrate` service before `api` (Alembic stamp + `upgrade
head`), so image upgrades apply schema changes without a manual migration step.
See [DEPLOY_PLATFORM.md](DEPLOY_PLATFORM.md) for the Compose vs Helm contract.

Seed a disposable demo graph after the API is healthy:

```bash
docker compose \
  -f deploy/docker-compose.platform.yml \
  -f deploy/docker-compose.hosted-poc.yml \
  exec api \
  agent-bom quickstart --run --offline --force
```

The compose profile persists `/root/.agent-bom` in a named volume so the seeded
demo graph survives container replacement. Offline quickstart inventories and
graphs the sample without package-CVE lookup; use the separate bundled demo
scan for offline CVE proof:

```bash
agent-bom scan --demo --offline
```

Replace the sample with real connected cloud scans as soon as the first account
is connected.

Before opening the host to testers, confirm the composed stack does not expose
API/UI ports on all interfaces and does not mount the placeholder Postgres
password:

```bash
python scripts/deploy/hosted_poc_preflight.py --write-secret
```

The preflight fails closed when required secrets are missing, the browser API
URL is still localhost, CORS is wildcarded, unauthenticated API mode is enabled,
API/UI ports bind publicly, required secrets are reused, audit integrity is
allowed to fall back to an ephemeral key, or the composed stack would mount
placeholder secrets. Run it again after any `.env`, DNS, or compose change.

Mint the first invited admin key from inside the API container so the key record
lands in the same persistent store used by the API:

```bash
docker compose \
  -f deploy/docker-compose.platform.yml \
  -f deploy/docker-compose.hosted-poc.yml \
  exec api \
  python scripts/deploy/mint_hosted_admin_key.py \
    --tenant-id customer-0 \
    --name customer-0-admin \
    --raw-key-file /tmp/customer0-admin.key
```

The JSON response includes key metadata only. The raw key is written once to the
private `0600` file passed with `--raw-key-file`; store that value in your
password manager, then delete or move the file into your secret store. Do not
commit it or paste it into docs, screenshots, tickets, or chat transcripts.

Run the hosted smoke before inviting anyone:

```bash
AGENT_BOM_SMOKE_URL="https://agent-bom.example.com" \
AGENT_BOM_SMOKE_API_KEY="<raw admin key>" \
scripts/deploy/hosted_poc_smoke.sh
```

After at least one cloud/Snowflake connection is stored, verify the broker path
without launching a full scan:

```bash
AGENT_BOM_SMOKE_URL="https://agent-bom.example.com" \
AGENT_BOM_SMOKE_API_KEY="<raw admin key>" \
AGENT_BOM_SMOKE_CONNECTION_ID="<connection id>" \
scripts/deploy/hosted_poc_smoke.sh
```

### Operator-managed invite endpoint

`scripts/deploy/mint_hosted_admin_key.py` is the bootstrap path for the very
first admin key. Once an operator holds an admin key, the same tenant-and-key
provisioning is available over the API without shelling into the container:

```bash
curl -sS -X POST https://agent-bom.example.com/v1/auth/invitations \
  -H "X-API-Key: <raw operator admin key>" \
  -H "Content-Type: application/json" \
  -d '{"organization": "Acme Corp", "email": "owner@acme.example"}'
```

The endpoint requires an authenticated admin in `AGENT_BOM_PLATFORM_OPERATOR_TENANT_ID` (default `default`), the `auth.keys:write` route scope, and a delegation ceiling permitting `*`. A customer tenant admin or a narrowly scoped operator cannot provision new tenants. It reuses the shared key-minting crypto — it does **not**
introduce a new key format. It:

- creates a **brand-new tenant** with a server-generated id (an invite can never
  target or leak into an existing tenant),
- mints one scoped API key for that tenant (default role `admin`), and
- returns a one-time invite payload: `raw_key` (shown once, never logged),
  `tenant_id`, `key_id`, `expires_at`, the applied default `quota`, and — only
  when `AGENT_BOM_HOSTED_INVITE_BASE_URL` is set — an `invite_url` sign-in link
  that never carries the key.

Authorization receipts are required in both the operator and destination audit histories before any tenant or key is provisioned. They include the actor tenant and key ID, destination and requested role, never the raw key. Receipt writes fail closed with HTTP 503; denied authorization creates neither a tenant nor a key. Audit and key stores are separate: an authorization receipt records an attempt, and key-store state establishes whether provisioning completed. Failed attempts remain in audit history.

Deliver the `raw_key` to the invited admin over a trusted channel; the operator
still owns who is invited and holds the manual revoke path (`DELETE
/v1/auth/keys/{key_id}`). The endpoint never accepts a provider secret or any
per-action credential — it mints a credential, it does not take one.

### Smallest defensible MVP defaults

The new tenant is bounded by the conservative default tenant quotas
(`active_scan_jobs`, `retained_scan_jobs`, `fleet_agents`, `schedules`) the
moment it is created — those defaults apply to any tenant with no overrides, and
per-tenant overrides are managed at `/v1/auth/quota`. For a multi-replica hosted
deploy, run the **Postgres** rate limiter and set
`AGENT_BOM_REQUIRE_SHARED_RATE_LIMIT=1` so rate limiting is cluster-safe and
fails closed rather than degrading to per-replica in-memory counters. See
`docs/operations/ENV_VARS.md` for the full rate-limit and quota env reference.

### Production auth checklist

For a gated POC, users are invited manually and access is revoked manually. Keep
the surface operator-controlled; this profile is not a public registration flow.

Before sharing the link, verify:

| Boundary | Required setting |
|---|---|
| Browser session | `AGENT_BOM_BROWSER_SESSION_SIGNING_KEY` is set, random, and stored as a secret. `AGENT_BOM_SESSION_COOKIE_SECURE=1` is enabled behind HTTPS. |
| API auth | `AGENT_BOM_API_KEY` or OIDC/SAML/proxy auth is configured. `AGENT_BOM_ALLOW_UNAUTHENTICATED_API` is unset. |
| Tenant binding | Each invited account has an explicit tenant. Do not use default-tenant OIDC/SAML fallbacks for multi-tenant testing. |
| Connection broker | `AGENT_BOM_CONNECTIONS_KEY` is a Fernet key and is never committed, logged, or reused across unrelated environments. |
| Audit integrity | `AGENT_BOM_AUDIT_HMAC_KEY` is set and survives restarts so audit signatures remain verifiable. |
| MCP read access | `AGENT_BOM_MCP_BEARER_TOKEN` must have an explicit `AGENT_BOM_MCP_BEARER_TOKEN_EXPIRES_AT` deadline within one hour; scope the deployment to its intended tenant/environment. |
| MCP write access | `AGENT_BOM_MCP_OPERATOR_TOKEN` is separate from the read token, requires its own `AGENT_BOM_MCP_OPERATOR_TOKEN_EXPIRES_AT` deadline within one hour, and is issued only to operators who need Shield/gateway write tools. |
| CORS/TLS | `CORS_ORIGINS` contains only your hosted URL and the internal UI origin. The front door terminates HTTPS; API/UI bind to loopback/private network only. |
| Usage control | Invitees have explicit scan windows, provider/account scope, and a manual revoke path before they connect a cloud or Snowflake account. |

If any row is unknown, stop and keep the deployment internal.

### Caddy front door

Example `Caddyfile`:

```caddyfile
agent-bom.example.com {
  encode zstd gzip

  reverse_proxy /v1/* localhost:8422
  reverse_proxy /health localhost:8422
  reverse_proxy /openapi.json localhost:8422
  reverse_proxy localhost:3000
}
```

Keep the front door as the only public listener. The Postgres container remains
internal and `deploy/docker-compose.hosted-poc.yml` binds the API/UI ports to
loopback, so they are reachable only from the proxy on the host.

The public demo is the static GitHub Pages site described above. Never enable
anonymous API access on an instance holding real connections or customer data.

### Proof checklist

Run this checklist before inviting anyone:

1. `https://agent-bom.example.com/health` returns healthy through the front door.
2. The UI opens at `https://agent-bom.example.com` and does not require direct
   access to ports `3000` or `8422`.
3. `AGENT_BOM_ALLOW_UNAUTHENTICATED_API` is unset.
4. A seeded scan appears in the dashboard with findings, graph, posture, and
   export links.
5. Connections can add at least one read-only cloud account or Snowflake
   account.
6. A connection scan hands off to scan details, findings, graph, jobs, and
   compliance surfaces.
7. Audit export and compliance export work for the tenant.

If any item fails, treat the instance as not ready for external users.

## Snowflake Native App lane

Use Snowflake when the buyer wants agent-bom to run inside their Snowflake
account. This is the stronger enterprise data-boundary story, but it has more
packaging steps than a self-hosted instance.

### CPU sizing

agent-bom is CPU-only. It scans packages, cloud metadata, IaC, graph evidence,
and model artifacts with lightweight static analysis. It does not perform GPU
model inference.

Use:

- `CPU_X64_XS` for the first smoke test.
- `CPU_X64_S` for a more comfortable POC with UI + API + scanner.

Do not use GPU pools for agent-bom.

### SPCS gate

Confirm the account can create a Snowpark Container Services pool:

```sql
USE ROLE ACCOUNTADMIN;

CREATE COMPUTE POOL AGENT_BOM_POC_POOL
  MIN_NODES = 1
  MAX_NODES = 1
  INSTANCE_FAMILY = CPU_X64_XS
  AUTO_RESUME = TRUE;

DROP COMPUTE POOL AGENT_BOM_POC_POOL;
```

If this succeeds, the account can run the Native App containers.

### Stand-up checklist

1. Run the Snowflake Native App package validation:

   ```bash
   gh workflow run release-snowflake.yml -f dry_run=true
   ```

2. Build and push the four release-tagged images to the Snowflake image
   repository:

   - `agent-bom`
   - `agent-bom-ui`
   - `agent-bom-scanner`
   - `agent-bom-mcp-runtime`

3. Create the application package and application in the demo account.
4. Bind only the references the demo needs: cloud asset tables, IAM tables,
   vulnerability tables, log tables, and artifact stages.
5. Leave advisory egress disabled unless the demo needs OSV, CISA KEV, EPSS,
   or GHSA enrichment.
6. Open the default web endpoint for the UI.
7. Run:

   ```sql
   CALL agent_bom.core.health_check();
   SHOW SERVICES IN APPLICATION agent_bom;
   ```

8. Enable optional services only when needed:

   ```sql
   CALL agent_bom.core.enable_scanner_service();
   CALL agent_bom.core.enable_mcp_runtime_service($mcp_bearer_token, $mcp_bearer_token_expires_at);
   ```

## What to avoid

- Do not present a self-hosted instance as anything beyond an invite-only POC
  until it has been through the production auth checklist.
- Do not ask testers for long-lived cloud keys when assumable roles work.
- Do not enable unauthenticated API access on an instance holding real
  connections. It is correct only for the anonymous seeded demo.
- Do not publish Grafana, observability, or development compose profiles.
- Do not run Snowflake GPU pools for agent-bom.
