# Managed trace connections

Use **Connections → Observability & SIEM** to select an operator-configured Langfuse
or LangSmith project and pull a bounded correlation sample. **Traces → Connect
platforms** opens the same hub. The browser sends a connection ID using the
existing Agent-Bom session; it does not receive provider credentials.

Agent-Bom SSO authenticates the user to the control plane. Provider authorization
is separate: these trace APIs use project/API keys. This adapter does not turn
a provider's dashboard SSO session into API access. Cloud connections retain their
existing role-assumption, workload-identity, and supported OAuth flows.

## Configure once, select on each use

The control-plane operator provisions scoped provider credentials in the existing
secret source (mounted files preferred). Do not put secrets in the binding JSON,
Git, UI URLs, tickets, or shell history. No new database credential store is used.

1. Mount a credentials JSON file from the deployment's secret manager. Langfuse
   requires exactly `public_key` and `secret_key`; LangSmith requires `api_key`.
   Set a reference such as `TRACE_PRODUCTION_CREDENTIALS_FILE` to its mounted path.
   The existing secret resolver prefers the `_FILE` variant over the environment
   value. Restrict file access to the control-plane service account.
2. Mount a binding file and set `AGENT_BOM_TRACE_CONNECTIONS_FILE` to its path:

   ```json
   {
     "production-traces": {
       "tenant_id": "tenant-a",
       "provider": "langfuse",
       "display_name": "Production traces",
       "endpoint": "https://cloud.langfuse.com",
       "credentials_env": "TRACE_PRODUCTION_CREDENTIALS",
       "enabled": true,
       "expires_at": "2027-01-01T00:00:00Z"
     }
   }
   ```

   Choose an expiry appropriate to the deployment. For LangSmith, set
   `provider` to `langsmith`, use its regional API endpoint, and add `project`
   with the exact project name. Public HTTPS validation still applies. The
   endpoint and project are bound by the operator and cannot be overridden in
   a managed pull request.
3. Start the configured API with `agent-bom api`, sign into the dashboard, then
   open **Connections → Observability & SIEM** and select the connection. A configured
   entry is not proof of provider access. **Pull and correlate** checks access
   and returns tool-call counts and finding links. It requires `runtime.ingest`.

For Helm, use `controlPlane.api.env`, `envFrom`, `extraVolumes`, and
`extraVolumeMounts` to supply these references and read-only secret mounts. For
Docker, mount the same files read-only and provide their `_FILE` references.
Neither path requires embedding provider keys in chart values or image layers.

## Rotation, revocation, and failure behavior

Bindings and secret files are read on every use. Update the mounted secret to
rotate a key. Disable/remove the binding or let its expiry elapse to stop new
pulls; revoke the upstream key for provider-side revocation. These changes do not
cancel a provider request already in flight. Environment-only secret changes
require a process restart.

Tenant/provider mismatch, missing or expired bindings, unavailable secrets, and
malformed configuration fail closed. There is no ambient credential fallback.
The audit records managed connection use with actor, tenant, provider, and
connection ID; this records credential use, not provider success.
Connection listings contain only tenant-visible IDs, labels, and providers;
secret references and plaintext are never returned. Request errors are generic.
Only control-plane operators can edit the binding configuration. Anyone with
`runtime.ingest` in the bound tenant can use its configured trace connections;
per-connection user grants are not implemented.

The advanced temporary-credentials form remains available for one-shot testing.
Content screening is off by default. Provider responses may still contain input
or output content; disabled screening excludes outputs from the adapted evidence.
Pull results are transient and do not populate the trace explorer. See the
[coverage and roadmap](ROADMAP.md) for incremental collection and persisted imports.

Contract tests: [broker boundaries](../tests/test_trace_connection_broker.py),
[content consent](../tests/test_trace_pull_screen_content.py), and
[browser workflow](../ui/e2e/trace-platform-connectors.spec.ts).
