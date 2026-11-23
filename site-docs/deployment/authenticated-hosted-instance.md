# Authenticated Self-Hosted Instance + Connect Your Cloud

This runbook stands up the **private customer / CISO experience**: a single-host,
**login-gated** `agent-bom` instance with **no synthetic data**, real
authentication, a least-privilege Postgres role, and a **real cloud account
connected read-only**. It is the deliberate opposite of the public anonymous
demo.

!!! danger "Keep customer evidence authenticated"
    Real cloud posture, findings and graph data belong behind the authenticated
    profile described here. The [public demo](https://koda-ai-studio.github.io/agent-bom/demo/)
    is a static GitHub Pages export of labelled sample JSON; it has no live API
    or cloud connections.

## Demo vs. authenticated product

| Setting | Public read-only demo | Authenticated product / secure hosted POC |
|---|---|---|
| Hosting | GitHub Pages static files | Your infrastructure and `docker-compose.platform.yml` |
| Overlay | None | `product.yml` or the `hosted-poc.yml` hardening overlay |
| Auth | Public sample files | API key and/or OIDC/SAML SSO |
| Cloud access | None | Your authorized read-only connection identity |
| Persistence | Bundled sample JSON | Postgres with a DML-only `agent_bom_app` role |
| Data | Labelled sample evidence | Your connected inventory, findings and graphs |

The product overlay is minimal on purpose: it flips the demo guards off,
forces the non-superuser app role via `:?` (fail-closed) env expansion, and
keeps browser-session cookies Secure. Auth env is wired by the platform base.
`hosted-poc.yml` alone is the **hardening** overlay (Secure cookies, loopback);
it does **not** enable anonymous API access.

## 0. Prerequisites

- A small CPU-only host (4 vCPU / 8–16 GB RAM) with Docker + Compose.
- DNS pointing at the host, for example `agent-bom.example.com`. Open inbound `443`
  only; restrict SSH to your IP.
- A checkout of this repository on the host.
- The `agent-bom` CLI on the host for the setup helpers (`pipx install agent-bom`).
  Commands that touch the running stack run inside the API container instead.

## 1. Stand up the gated instance

### 1a. Generate secrets and the non-superuser DB role

The app connects as `agent_bom_app`, the DML-only role created by
`deploy/supabase/postgres/init.sql` on first boot. Provide its secret via
`deploy/secrets/postgres_app_password` (Docker secret mount); the init wrapper
reads that file and the init SQL creates the role `NOSUPERUSER NOBYPASSRLS`,
satisfying the RLS superuser guard (#3665) by least privilege. Never put
Postgres or control-plane secrets in `.env` or compose environment variables.

```bash
cp .env.example .env

# Public URL wiring (Caddy terminates TLS on 443)
export AGENT_BOM_HOSTED_DOMAIN="agent-bom.example.com"
export ACME_EMAIL="ops@example.com"
export NEXT_PUBLIC_API_URL="https://agent-bom.example.com"
export CORS_ORIGINS="https://agent-bom.example.com,http://ui:3000"

# Secrets: file mounts only (Postgres + control-plane)
python scripts/deploy/hosted_poc_preflight.py --write-secret --skip-compose
# Or see deploy/secrets/README.md
```

The `api_key` secret file seeds a single **admin** key via
`AGENT_BOM_API_KEY_FILE`. To seed viewer/analyst keys from a file instead of
(or in addition to) OIDC, write `deploy/secrets/api_keys` with
`<raw-key>:viewer,<raw-key>:analyst` and mount it as `AGENT_BOM_API_KEYS_FILE`.

### 1b. Optional — wire OIDC / SAML SSO instead of (or alongside) API keys

The API container reads OIDC settings from `deploy/secrets/oidc.env`; variables
exported in your shell never reach it. Write that file with the setup helper:

```bash
agent-bom auth setup-oidc --provider generic \
  --issuer "https://login.example.com/" \
  --client-id agent-bom \
  --base-url "https://agent-bom.example.com" \
  --role-claim agent_bom_role \
  --client-secret-file /run/agent-bom/oidc/client_secret \
  --write --yes
```

Put the IdP client secret in `deploy/secrets/oidc/client_secret`; Compose mounts
that directory read-only at `/run/agent-bom/oidc`. Omit `--client-secret-file`
for a PKCE public client. For multi-tenant IdP setups add
`AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON` to the same file. The preflight in step 1e
fails if an `AGENT_BOM_OIDC_*` value is exported in the shell but missing from
the file.

The CLI refuses to expose the API on a non-loopback host unless **at least one**
of API key, `AGENT_BOM_API_KEYS`, OIDC, or a SCIM bearer token is configured, so
the gated posture is enforced at boot, not just documented.

### 1c. Boot the authenticated stack

```bash
docker compose \
  -f deploy/docker-compose.platform.yml \
  -f deploy/docker-compose.product.yml \
  up -d --build

docker compose \
  -f deploy/docker-compose.platform.yml \
  -f deploy/docker-compose.product.yml \
  ps
```

The platform base binds API (`8422`) and UI (`3000`) to loopback. Do **not**
seed a demo graph — the product overlay sets `AGENT_BOM_DEMO_ESTATE=0`.

### 1d. Front door: TLS via Caddy

Run Caddy on the host as the only public listener, reusing the shipped
`deploy/caddy/Caddyfile.hosted-poc` (it already splits `/v1/*`, `/health`, and
`/ws/*` to `127.0.0.1:8422` and everything else to `127.0.0.1:3000`, and sets
HSTS/security headers). `AGENT_BOM_HOSTED_DOMAIN` and `ACME_EMAIL` from step 1a
drive its TLS.

```bash
caddy run --config deploy/caddy/Caddyfile.hosted-poc
```

### 1e. Preflight (fail-closed)

```bash
python scripts/deploy/hosted_poc_preflight.py --write-secret
```

This fails closed when required secrets are missing, `AGENT_BOM_ALLOW_UNAUTHENTICATED_API`
is enabled, CORS is wildcarded, or API/UI ports bind publicly. Re-run it after
any `.env`, DNS, or compose change.

## 2. Create the first admin and issue a viewer/analyst key

Mint the first admin key **inside the API container** so the record lands in the
same persistent store the API reads:

```bash
docker compose \
  -f deploy/docker-compose.platform.yml \
  -f deploy/docker-compose.product.yml \
  exec api \
  agent-bom auth mint-admin-key \
    --tenant-id customer-0 \
    --name customer-0-admin \
    --raw-key-file /tmp/customer0-admin.key
```

The command prints key metadata only; the raw key is written once to the `0600`
file inside the container. Copy it out, then remove it from the container:

```bash
COMPOSE="docker compose -f deploy/docker-compose.platform.yml -f deploy/docker-compose.product.yml"
$COMPOSE cp api:/tmp/customer0-admin.key ./customer0-admin.key && chmod 600 ./customer0-admin.key
$COMPOSE exec api rm /tmp/customer0-admin.key
```

Store it in your password manager, then delete the local copy; never commit,
screenshot, or paste it.

The key expires after 30 days by default (`AGENT_BOM_API_KEY_DEFAULT_TTL_SECONDS`;
at most 90 days, `AGENT_BOM_API_KEY_MAX_TTL_SECONDS`); pass `--expires-at` for an
earlier date, and issue the next admin key through `POST /v1/auth/keys` before it
lapses.

Issue scoped viewer/analyst keys for the account with the admin key against the
RBAC endpoint (`POST /v1/auth/keys` requires the `admin` role):

```bash
curl -sS -X POST "https://agent-bom.example.com/v1/auth/keys" \
  -H "Authorization: Bearer <raw admin key>" \
  -H "Content-Type: application/json" \
  -d '{"name": "ciso-viewer", "role": "viewer"}'
```

If you wired OIDC in step 1b instead, skip key issuance and map IdP group claims
to roles via `AGENT_BOM_OIDC_ROLE_CLAIM`; each invited user signs in at
`/login`.

## 3. Connect a real cloud account read-only

`agent-bom` never mutates the target and does no cloud I/O until you opt in. Use
the built-in onboarding helper to print the exact read-only setup and confirm
your credentials are detectable:

```bash
agent-bom connect aws --emit --out agent-bom-aws-readonly.json
```

Deploy the emitted CloudFormation artifact, then establish the connection with
its role ARN and ExternalId. This path works from the installed wheel.

### 3a. Optional source-checkout Terraform (AWS)

For teams that already use a repository checkout and Terraform state,
`deploy/terraform/connect-aws` mints the same least-privilege role: AWS-managed
`SecurityAudit` (+ optional `ViewOnlyAccess`), a unique non-guessable name, and
an **always-enforced high-entropy `sts:ExternalId`**. No access keys, no
write permissions.

```bash
cd deploy/terraform/connect-aws
terraform init
terraform apply \
  -var 'trusted_principal_arns=["arn:aws:iam::<scanner-acct>:role/agent-bom-scanner"]'

terraform output -raw role_arn        # the read-only role to assume
terraform output -raw external_id     # sensitive; confused-deputy defense
```

GCP and Azure follow the same pattern with their own modules:
`deploy/terraform/connect-gcp` (viewer + `iam.securityReviewer`, keyless
Workload Identity Federation) and `deploy/terraform/connect-azure` (Reader +
Security Reader, pinned federated identity credential).

### 3b. Run the first scan into the tenant

Dashboard findings come from the control plane's **Connections**: a connection
belongs to the tenant of the key or SSO session that created it, and its scans
persist to that tenant's stores. A CLI scan run with `docker compose exec`
writes the CLI's own local report instead, and none of it reaches the dashboard.

The API container assumes the customer role with its own AWS identity, so that
identity must be listed in the role's trusted principals (`trusted_principal_arns`
in step 3a). On EC2, attach an instance profile with that role and raise the
instance metadata hop limit to 2 so containers can read it:

```bash
aws ec2 modify-instance-metadata-options --instance-id <host-instance-id> \
  --http-tokens required --http-put-response-hop-limit 2
```

Then either sign in, open **Connections**, and add the AWS account with the role
ARN and ExternalId, or make the same call with the admin key:

```bash
export ABOM_URL="https://agent-bom.example.com"
export ABOM_KEY="$(cat ./customer0-admin.key)"

curl -sS -X POST "$ABOM_URL/v1/cloud/connections" \
  -H "Authorization: Bearer $ABOM_KEY" \
  -H "Content-Type: application/json" \
  -d '{"provider": "aws", "display_name": "Production",
       "role_ref": "arn:aws:iam::<account-id>:role/<read-only-role>",
       "external_id": "<external id>", "regions": ["us-east-1"]}'
```

The response carries the connection `id` and the first scan's job id in
`last_scan_id`; the scan starts on creation. Check it, verify the broker, or
re-scan:

```bash
curl -sS "$ABOM_URL/v1/scan/<last_scan_id>" -H "Authorization: Bearer $ABOM_KEY"
curl -sS -X POST "$ABOM_URL/v1/cloud/connections/<id>/test" -H "Authorization: Bearer $ABOM_KEY"
curl -sS -X POST "$ABOM_URL/v1/cloud/connections/<id>/scan" -H "Authorization: Bearer $ABOM_KEY"
```

Azure and GCP connections take the same call with `"provider": "azure"` or
`"gcp"`; their `role_ref`, `auth_params`, and keyless workload-identity options
are in
[`docs/CLOUD_CONNECT.md`](https://github.com/koda-ai-studio/agent-bom/blob/main/docs/CLOUD_CONNECT.md),
together with organization fan-out (`"inventory_scope": "organization"`) and
scale caps.

## 4. Log in and see real posture

1. Open `https://agent-bom.example.com` and sign in at `/login` (API key or SSO).
2. Confirm the dashboard shows the connected account's **real** findings, CIS
   benchmark posture, and blast-radius graph — not the demo estate.
3. Run the smoke check before inviting others:

   ```bash
   AGENT_BOM_SMOKE_URL="https://agent-bom.example.com" \
   AGENT_BOM_SMOKE_API_KEY="<raw admin key>" \
   scripts/deploy/hosted_poc_smoke.sh
   ```

## Verify the gated posture

Re-confirm the anti-demo guards any time you change config:

```bash
docker compose \
  -f deploy/docker-compose.platform.yml \
  -f deploy/docker-compose.product.yml \
  config | grep -E 'AGENT_BOM_DEMO_ESTATE|AGENT_BOM_ALLOW_UNAUTHENTICATED_API|AGENT_BOM_POSTGRES_URL'
# expect: DEMO_ESTATE "0", ALLOW_UNAUTHENTICATED_API "0",
#         POSTGRES_URL using agent_bom_app (never the admin owner)
```

If `AGENT_BOM_ALLOW_UNAUTHENTICATED_API` is anything but `0`, or the Postgres
URL is not using `agent_bom_app`, stop and fix before connecting any cloud.

## Related

- Public anonymous demo runbook: [`docs/HOSTED_POC.md`](https://github.com/koda-ai-studio/agent-bom/blob/main/docs/HOSTED_POC.md)
- Cloud connect reference: [`docs/CLOUD_CONNECT.md`](https://github.com/koda-ai-studio/agent-bom/blob/main/docs/CLOUD_CONNECT.md)
- Auth model and tenancy: [Enterprise Auth and Tenancy](enterprise-auth-and-tenancy.md)
