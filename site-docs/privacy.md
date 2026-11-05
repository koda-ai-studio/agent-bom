# Privacy notice

> **DRAFT — Owner review required before publication.** This is a technical
> description for review, not an effective legal notice. The service owner must
> confirm its identity, contact process, hosting and identity-provider retention,
> and applicable legal requirements before publishing or submitting a directory listing.

## Scope and information processed

agent-bom is security scanning software that can run locally or in an
operator-controlled service. These modes have different data boundaries.

Local directory plugins run selected inventory, package, configuration and skill
checks. Depending on the requested tool, inputs include package names and
versions, selected file paths and contents, MCP server definitions, environment
variable names, vulnerability identifiers and findings. Discovery can read known
client configuration locations; preview them with `agent-bom where --dry-run`.
Directory skills and the audit profile do not expose the `agent_activity` tool
or a skill for reading chat history. Other explicitly selected standalone
features have their own permissions; installing a directory plugin does not
authorize them.

The agent-bom-guard plugin adds one hook. Claude Code passes it the text of
every Bash command before it runs, and it parses that text on your machine to
find package installs. It stores nothing and writes no files. With its `osv_lookup`
option on, which is the default, it sends the name, ecosystem and pinned version of
each package an install names to `api.osv.dev`, even when the install uses a custom
registry, so a private package name reaches that service unless the option is off.
It sends no command text, paths, file contents, environment variables or credentials.

No directory plugin reads Claude or Codex chat history, session files or memory.
`~/.claude.json` is read for its MCP server entries; the prompt history it also holds
is not used or returned.

A remote MCP service receives the tool name and arguments sent by the client,
including any supplied paths, package names or evidence, and returns tool
results to that client. Remote paths refer to the server's filesystem, not the
client's computer. The client and its AI provider may retain those messages
under their own policies. Do not submit secrets or personal information that
the selected scan does not require. Redaction reduces exposure but is not a
guarantee that arbitrary input is free of sensitive information.

## Destinations

Package and vulnerability lookups can send package names, versions, advisory
IDs and repository coordinates to OSV, NVD, FIRST EPSS, CISA, npm, PyPI and
OpenSSF Scorecard. Installation through `uvx` downloads software from the
configured package index. These providers also receive ordinary network
request metadata. The scanner's lookup requests do not upload entire project
files. Offline scanning uses available local evidence and can have coverage gaps.

Refreshing the local advisory database, which no directory skill does on its own,
downloads public feeds from `osv-vulnerabilities.storage.googleapis.com`,
`secdb.alpinelinux.org`, `security-tracker.debian.org`, `deb.freexian.com`,
`epss.empiricalsecurity.com`, CISA and NVD, and sends no package or project data.

The agent-bom Claude plugin starts its servers with `GITHUB_TOKEN`, `GH_TOKEN` and
`NVD_API_KEY` blanked. When agent-bom runs from a shell, as the Codex skills do, a
`GITHUB_TOKEN` or `GH_TOKEN` already in that environment is sent only to
`api.github.com`, and `NVD_API_KEY` only to `services.nvd.nist.gov`, to raise rate limits.

Hosted OAuth sends users to the configured authorization server for login and
consent. The MCP service validates the access token's issuer, subject, tenant,
audience and expiry, then sends that token to the same issuer's configured
introspection endpoint to check whether it remains active. Passwords are
entered at the authorization server; the MCP service does not implement a
password-login form. Authentication, hosting and identity-provider logs are
subject to those operators' configurations.

Explicitly configured control-plane pushes, exports, cloud connectors, webhooks
and telemetry collectors have separate destinations and permissions. They are
not enabled by installing a directory skill. The
[permissions contract](https://github.com/koda-ai-studio/agent-bom/blob/main/docs/PERMISSIONS.md)
lists the supported destinations and opt-in behavior.

## Storage and retention

- Local report files remain until the user or an operator removes them.
  Local rescan summaries retain one bounded identity summary per target, up to
  200 targets by default; `AGENT_BOM_NO_SCAN_MEMORY=1` disables that feature.
- The MCP scan-result store uses SQLite or configured PostgreSQL. Its default
  readable lifetime is **30 minutes**, configurable by
  `AGENT_BOM_MCP_SCAN_RESULT_TTL_SECONDS`, with four results per tenant by
  default. Expired rows are removed when a subsequent result is stored;
  expiration is **not a guaranteed deletion deadline** for database files,
  backups or replicas. Cached results are bound to a tenant and caller token;
  token rotation prevents access to the preceding token's cached results.
- Recent MCP request traces are held in process memory, bounded to 256 entries
  by default. Operational logs, persisted inventory, audit records and backups
  have operator-controlled retention. This code does not impose one universal
  deletion period on every deployment or external provider.
- The resource server caches public verification keys for five minutes. It
  checks token activity on each HTTP authentication request without caching a
  successful introspection decision. Client-side refresh-token storage belongs
  to the MCP client and authorization server.

The hosted service's actual log, backup and identity-account retention periods
must be supplied by its owner before this draft becomes an effective notice.
Self-hosted operators must document their own settings and deletion process.

## Purposes and your controls

The information above is processed only to produce the security result you asked for.
There is no telemetry, advertising or profiling in the plugins. You can preview what
is read with `agent-bom where --dry-run`, turn off network lookups with offline mode or
the guard's `osv_lookup` option, turn off rescan summaries with
`AGENT_BOM_NO_SCAN_MEMORY=1`, and delete local data by removing `~/.agent-bom`.

## Access and questions

Contact the service operator for access, correction or deletion requests about
its stored data. Use the project's
[support channel](https://github.com/koda-ai-studio/agent-bom/issues) for general
questions without including private records. Report security concerns through
[the private reporting instructions](https://github.com/koda-ai-studio/agent-bom/security/policy).
No certification or regulatory compliance status is asserted by this notice.
