# Compose secrets directory

Used by `deploy/docker-compose.platform.yml` and
`deploy/docker-compose.fullstack.yml` to mount credentials as files instead of
env vars.
Secrets must never live in `.env`, compose interpolation, or git.

Populate before `docker compose up` (or run
`python scripts/deploy/hosted_poc_preflight.py --write-secret --skip-compose`):

```bash
umask 077
mkdir -p deploy/secrets

# Postgres: bootstrap/admin (init+migrations), app (tenant-bound runtime), and
# trusted maintenance (scoped cross-tenant work) use independent credentials.
printf %s "$(openssl rand -hex 32)" > deploy/secrets/postgres_password
printf %s "$(openssl rand -hex 32)" > deploy/secrets/postgres_app_password
printf %s "$(openssl rand -hex 32)" > deploy/secrets/postgres_maintenance_password

# Control-plane crypto / auth material
printf %s "$(openssl rand -hex 32)" > deploy/secrets/api_key
printf %s "$(openssl rand -hex 32)" > deploy/secrets/audit_hmac_key
printf %s "$(openssl rand -hex 32)" > deploy/secrets/browser_session_signing_key
printf %s "$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')" \
  > deploy/secrets/connections_key

# Optional (mount manually or via preflight --write-secret)
# printf %s "$(openssl rand -hex 32)" > deploy/secrets/rate_limit_key
# printf %s "$(openssl rand -hex 32)" > deploy/secrets/trust_proxy_auth_secret
# printf %s "$(openssl rand -hex 32)" > deploy/secrets/scim_bearer_token

# Optional confidential OIDC client: provision this value from the IdP or
# secret manager. Compose mounts only this dedicated directory read-only.
# install -m 0600 /secure/path/to/oidc-client-secret \
#   deploy/secrets/oidc/client_secret

# Owner and your primary group only. Never world-readable.
chgrp "$(id -g)" deploy/secrets/*
chmod 0640 deploy/secrets/postgres_password deploy/secrets/postgres_app_password \
  deploy/secrets/postgres_maintenance_password \
  deploy/secrets/api_key deploy/secrets/audit_hmac_key \
  deploy/secrets/browser_session_signing_key deploy/secrets/connections_key
```

`make secrets` creates files with mode 0640, owner plus your primary group, and
repairs existing files without replacing their contents. It refuses symlink
destinations.

Compose bind-mounts a secret file with its host owner and mode; the long-syntax
`uid`, `gid` and `mode` fields do not apply. The containers run as other non-root
users (postgres is UID 70), so on Linux a 0600 file is unreadable inside them. Each
service that reads secrets joins your group through `group_add`, and Postgres starts
directly as its own user because the image's privilege drop discards extra groups.
`make platform-up` and `make fullstack-up` set `AGENT_BOM_SECRETS_GID`; for a direct
`docker compose up`, run `export AGENT_BOM_SECRETS_GID=$(id -g)` first, or those
services cannot read the files and fail to start.

Anyone else in your primary group can read these files, so run this under an account
whose primary group is private to it. Rootless Docker maps group IDs differently and
has not been verified; provision per-service secret mounts there instead.

`*.example` files are non-secret documentation placeholders only.
Compose defaults to the real `deploy/secrets/*` paths so a shared stack fails
closed if a real secret file is missing.

The API reads `AGENT_BOM_*_FILE` mounts (file wins over plain env). Helm may
still inject via Secret→env; compose/local is file-only. This file-first
resolution also covers the signing PEMs, so a mounted file works everywhere the
inline env var did:

- `AGENT_BOM_OAUTH_AS_PRIVATE_KEY_PEM_FILE` — RSA PEM for the OAuth AS token
  signing key (unset → ephemeral per-restart key).
- `AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM_FILE` — Ed25519 PEM for
  compliance-bundle signing (unset → HMAC-SHA256 fallback).

The API's tenant-bound traffic uses `agent_bom_app`; scoped cross-tenant jobs
use `agent_bom_maintenance` through a separately validated pool. The API never
uses the Postgres bootstrap/admin role, which is reserved for init/migrations.
