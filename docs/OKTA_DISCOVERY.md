# Okta machine identity discovery

Enable read-only discovery during an Agent-Bom scan. Applications and API-token
metadata become normalized identities, with explicit collection coverage and an
organization-scoped graph. No token values or client secrets are retained.

## First command

Configure an Okta service app with `private_key_jwt`, DPoP enabled, the
`okta.apps.read` and `okta.apiTokens.read` grants, and an appropriate read-only
administrator role. Register its public signing JWK in Okta; keep the private
RSA key locally in an owner-only PEM file (at least 2048 bits).

```bash
chmod 600 /private/path/okta-signing.pem
export AGENT_BOM_OKTA_DISCOVERY=1
export AGENT_BOM_OKTA_ORG_URL=https://your-org.okta.com
export AGENT_BOM_OKTA_CLIENT_ID=your-service-app-client-id
export AGENT_BOM_OKTA_KEY_ID=your-public-jwk-kid
export AGENT_BOM_OKTA_PRIVATE_KEY_FILE=/private/path/okta-signing.pem
agent-bom scan -p . --format json --output scan.json
```

OAuth uses a short-lived client assertion and an ephemeral DPoP key. Access
tokens stay in memory. The client requests only the two discovery scopes and
rejects a token with a different scope set or without DPoP binding. There is no
fallback to client-secret authentication. Existing SSWS integrations can instead
set `AGENT_BOM_OKTA_TOKEN` and leave the OAuth client ID unset.

Only HTTPS tenant origins under `okta.com`, `oktapreview.com`, or `okta-emea.com`
are accepted. Custom domains are not currently supported. Local PEM loading
requires POSIX owner-only file permissions and rejects symlinks.

## Artifact and next step

Inspect the report's `identity_discovery` block for provider status, coverage,
normalized identities, and safe warnings. The normal graph builder projects
identities and their observed organization membership. Native IDs are scoped to
the organization; matching names do not create cross-vendor relationships.

The opt-in `nhi_discover` MCP tool consumes the same discovery path. Import the
scan into a tenant-authenticated control plane to explore the retained evidence.

## Evidence boundaries

- Enumerates service applications and API-token metadata, including configured
  authentication method and DPoP setting when present in the provider response.
- Follows same-origin, same-endpoint pagination, bounded to 20 pages, 2,000
  records per collection, and 2 MiB per response. Redirects are not followed.
- Failed, malformed, duplicate, or bounded collections produce incomplete
  coverage. An unsuccessful collection is not an empty successful result.
- OAuth `grant_types` describe protocol flows; they are not granted permissions.
  App consent grants, effective privileges, users, groups, and System Log events
  are not collected by this path.
- `lastUpdated` is retained as configuration metadata, never last-use evidence.
  Usage remains unknown. Empty discovery does not establish clean posture.
- This collector does not perform remediation or create identities. The token
  endpoint POST authenticates the reader; resource discovery uses GET only.

See [Okta service-app authentication](https://developer.okta.com/docs/guides/implement-oauth-for-okta-serviceapp/)
and [DPoP for Okta APIs](https://developer.okta.com/docs/guides/dpop/oktaresourceserver/main/).
