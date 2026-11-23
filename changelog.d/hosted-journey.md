### Added
- `agent-bom auth mint-admin-key` mints the first admin API key of a self-hosted control plane. It ships in the package, so it runs inside the published image; the hosted runbooks used a repository script the image does not contain. On a fresh Postgres it creates the tenant and its first key together under row-level security, as tenant invitations do; the old script failed there because the tenant did not exist yet.

### Fixed
- The authenticated hosted guide's first scan now goes through a cloud connection created with the tenant's admin key (or the dashboard's Connections page), so findings land in that tenant's dashboard; the old `docker compose exec ... agent-bom agents` step wrote only the CLI's local report.
- The hosted guide's SSO step writes `deploy/secrets/oidc.env` with `agent-bom auth setup-oidc --write`; shell exports never reached the API container. The hosted preflight now fails when an `AGENT_BOM_OIDC_*` value is exported but missing from that file.
- The guide shows how to copy the one-time admin key out of the container, and the hosted POC guide names the state path the image actually uses.
