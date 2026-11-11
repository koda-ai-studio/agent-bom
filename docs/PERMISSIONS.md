# Permissions & Trust Contract

agent-bom's scanner lane is **read-only by default**. This document is an
explicit, auditable contract of what the local scan path accesses — and what it
never touches. Every capability that goes beyond read-only (disk side-scan,
live MCP introspection, proxy/gateway enforcement, proxy rollout, dependency
remediation, ticket filing, outbound destinations) is opt-in and is scoped in
[SECURITY.md — Trust model and permissions](../SECURITY.md#trust-model-and-permissions).

---

## What We Read

Keyless image verification uses offline cached/bundled Sigstore trust material
and performs no trust-service network requests. The separately invoked trust
refresh command in `docs/IMAGE_SECURITY.md` contacts
`https://tuf-repo-cdn.sigstore.dev` for signed public trust metadata. It sends no
image contents, credentials or scan report. Bundle downloads use the same
bounded registry connection as image evidence discovery.

agent-bom reads only what you explicitly ask it to scan:

| Target | How specified | What is read |
|--------|--------------|--------------|
| Agent configs | auto-discovery or `--project` | Config JSON/YAML files (e.g. `claude_desktop_config.json`) |
| Inventory | `--inventory` | Your inventory JSON file |
| Lock files | inferred from project | `package-lock.json`, `requirements.txt`, `Cargo.lock`, etc. |
| Docker images | `--image` | Image filesystem layers (via container inspection subprocess) |
| Kubernetes | `--k8s` | get/list on namespaces, pods, workloads (Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob), service accounts and RBAC objects, via `kubectl` or the in-cluster API (read-only; Secrets are never listed) |
| Terraform | `--tf-dir` | `.tf` source files (no state files, no `.tfvars`) |
| GitHub Actions | `--gha` | `.github/workflows/*.yml` files; reports AI/credential use plus unpinned remote actions, `pull_request_target`, and missing top-level `permissions:` policies |
| SBOM files | `--sbom` | CycloneDX JSON/XML or SPDX JSON/tag-value you provide |
| Ollama models | `--ollama`, optionally `--ollama-host` or `OLLAMA_HOST` | `GET /api/tags` on the selected endpoint; no inference or model downloads. Only the implicit localhost default can fall back to local model manifests. |
| Self-hosted serving endpoints | `--serving-endpoint RUNTIME=URL` (repeatable; `vllm`, `tgi`, `triton`, `llamacpp`, `lmstudio`) | The runtime's documented model listing and metadata reads on that endpoint only, such as `GET /v1/models`, `GET /info` or Triton's `POST /v2/repository/index` listing request; no inference, model loads or downloads. No credentials are sent unless `--serving-token-env URL=AGENT_BOM_SERVING_TOKEN_<NAME>` pairs that endpoint with a bearer token (see below). A failed endpoint never falls back to local files. |

**Bearer tokens for protected serving endpoints.** `--serving-token-env
URL=ENV_NAME` sends `Authorization: Bearer <token>` to exactly one
`--serving-endpoint` URL. The command line carries only the variable's name:

- `ENV_NAME` must start with `AGENT_BOM_SERVING_TOKEN_`, so an unrelated
  secret such as a cloud key cannot be sent by mistake.
- The token is read from the file named by `ENV_NAME_FILE` when that is set
  (it wins), otherwise from `ENV_NAME`. This is the same convention as the
  control-plane secrets (`resolve_secret`).
- The token is sent only over `https` or to a loopback address, only to the
  paired endpoint, and never on a redirect, because redirects are not
  followed.
- A pairing for an endpoint that is not probed, or a token with characters a
  bearer token cannot carry, is refused before any request is sent.
- Evidence records `collection.request_identity: bearer` or `anonymous`,
  never the value. A rejected token reads as `denied`.

Ollama API inventory records the endpoint as a runtime probe. An unavailable
configured endpoint reports incomplete discovery and never substitutes this
machine's downloaded models. Default local-manifest fallback reports its own
filesystem scope and a warning; downloaded artifacts do not prove that models
are currently being served. Endpoint inventory does not establish TLS/auth
configuration, effective access, public reachability, or compliance.

The MCP tools `kspm_cluster_posture` and `kspm_workload_inventory` require
`live=true` on each call before using Kubernetes credentials or contacting a
cluster. Set `AGENT_BOM_MCP_LIVE_INTROSPECTION=0` on the server to refuse these
reads even when a caller opts in. Refused calls return `status=not_collected`,
not an empty posture result. When enabled, the response records collector
coverage; use its findings and graph inventory to choose the next scan.

Run `agent-bom agents --gha . --offline` to inspect workflow files without
network access. Pipeline-hardening gaps appear as scan warnings; pin remote
actions and reusable workflows to full commit SHAs, avoid executing untrusted
pull-request code under `pull_request_target`, and declare least-privilege
top-level `permissions:` before rerunning the same command.

---

## Auto-Discovery Config Paths

**Auto-discovery** reads known client and project paths for supported agent
surfaces. Most entries are fixed file paths; some supported clients use bounded
project or profile globs so teams can find the same configs their tools load.
If a file does not exist, it is silently skipped.

### Global config files

| Client | macOS path | Linux path |
|--------|-----------|------------|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` | `~/.config/Claude/claude_desktop_config.json` |
| Claude Code | `~/.claude/settings.json`, `~/.claude.json` | same |
| Cursor | `~/Library/Application Support/Cursor/User/globalStorage/cursor.mcp/mcp.json`, `~/.cursor/mcp.json` | `~/.config/Cursor/User/globalStorage/cursor.mcp/mcp.json`, `~/.cursor/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json`, `~/.codeium/windsurf-next/mcp_config.json`, `~/.codeium/mcp_config.json`, `~/.config/devin/mcp_config.json`, `~/.windsurf/mcp.json`, `~/Library/Application Support/Windsurf/User/globalStorage/windsurf.mcp/mcp.json` | `~/.codeium/windsurf/mcp_config.json`, `~/.codeium/windsurf-next/mcp_config.json`, `~/.codeium/mcp_config.json`, `~/.config/devin/mcp_config.json`, `~/.windsurf/mcp.json` |
| Cline (VS Code, CLI) | `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`, `~/.cline/data/settings/cline_mcp_settings.json` | `~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`, `~/.cline/data/settings/cline_mcp_settings.json` |
| VS Code Copilot | `~/Library/Application Support/Code/User/mcp.json` | `~/.config/Code/User/mcp.json` |
| Continue.dev | `~/.continue/config.yaml`, legacy `~/.continue/config.json` | same |
| Zed | `~/.config/zed/settings.json` | same |
| OpenClaw | `~/.openclaw/openclaw.json` | same |
| Cortex Code | `~/.snowflake/cortex/mcp.json` | same |
| Docker MCP Toolkit | `~/.docker/mcp/registry.yaml`, `~/.docker/mcp/catalogs/docker-mcp.yaml` | same |

### Project-level config files (current working directory only)

- `.mcp.json`
- `mcp.json`
- `.cursor/mcp.json`
- `.vscode/mcp.json`
- `.openclaw/openclaw.json`

### Docker Compose files (current working directory only)

- `docker-compose.yml`
- `docker-compose.yaml`
- `compose.yml`
- `compose.yaml`

The exact path set changes as supported clients are added. Use
`agent-bom where --json` or `agent-bom where --dry-run` to preview the paths
that would be read on a given machine before any scan runs.

Default discovery stays scoped to known agent, MCP, Docker Compose, JetBrains,
and project config surfaces; arbitrary filesystem crawling is not part of
auto-discovery.

---

## What We Extract From Config Files

From each MCP client config, agent-bom extracts:

| Data element | Example | Used for |
|-------------|---------|----------|
| Server name | `"filesystem"` | Inventory labeling |
| Command | `"npx"` | Package identification |
| Arguments | `["@modelcontextprotocol/server-filesystem", "/path"]` | Package name + version extraction |
| Env var **names** | `"OPENAI_API_KEY"` | Credential exposure mapping |

### What is NOT extracted

- **Environment variable values** — only names are read, never values
- **File path arguments** — shown in inventory but never traversed or opened
- **Config file contents** — only the structured server definitions are parsed

### Credential name detection

Env var names matching these patterns are flagged as credential-like:

**Flagged**: `*KEY*`, `*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*CREDENTIAL*`, `*API_KEY*`, `*APIKEY*`, `*AUTH*`, `*PRIVATE*`, `*CONNECTION*`, `*CONN_STR*`, `*DATABASE_URL*`, `*DB_URL*`

**Excluded** (standard system vars): `PATH`, `HOME`, `LANG`, `SHELL`, `USER`, `TERM`, `EDITOR`, `DISPLAY`, `PWD`, `TMPDIR`

Credential values are **never** read, stored, logged, or transmitted. Only names appear in reports as blast-radius indicators.

---

## What We Never Do

These hold for the default scan path. The opt-in capabilities listed in
[SECURITY.md](../SECURITY.md#trust-model-and-permissions) are the only
exceptions, and each needs an explicit flag or setting.

- **Never write** to any config file, lock file, or project file (only
  `runtime configure --apply`, `proxy-bootstrap --apply`, and
  `remediate --apply` do, on request)
- **Never execute** MCP servers or agent processes (only `--introspect` and
  the runtime proxy do, on request)
- **Never store** credential values — only env var _names_ appear in reports
- **Never transmit** your file contents, project structure, or inventory to external services unless you explicitly enable a push, export, or integration destination; pushed payloads are sanitized before transmission
- **Never cache** any personal data to disk (scan history is opt-in via `--save`)
- **Remembers only identities between local scans**: outside CI, each scan target keeps one small summary
  under `$AGENT_BOM_STATE_DIR/last-scan/` (default `~/.agent-bom/last-scan/`, owner-only, at most 200 targets)
  holding advisory ids, package names, and MCP server and tool ids with redacted names, so a rescan can print
  what changed. It stores no paths, file contents or credential values; `AGENT_BOM_NO_SCAN_MEMORY=1` turns it off.
  The one-time GitHub star tip writes an empty `hints/star-shown` marker there; `AGENT_BOM_NO_HINTS=1` turns tips off.
- **Never require** authentication tokens or API keys (NVD key is optional for rate limits only)
- **Never access** arbitrary files outside the supported discovery surfaces you choose to scan
- **Never perform** broad recursive filesystem crawls during auto-discovery
- **Never run** background processes, daemons, cron jobs, or system services as part of a scan

---

## Scanner and Enrichment API Calls

Scanner and enrichment network calls are read-only GET/POST requests to public
vulnerability and package metadata databases. Only package names, versions,
CVE IDs, or repository coordinates needed for that lookup are sent. No config
contents or credential values are included in those requests.

| Service | URL | What we send | What we receive | Auth |
|---------|-----|-------------|----------------|------|
| OSV.dev | `https://api.osv.dev/v1/querybatch` | Package names + versions | CVE IDs, advisories | None |
| OSV.dev (advisory and CVE records) | `https://api.osv.dev/v1/vulns/{id}` | Advisory or CVE IDs | Advisory details; for a distro advisory with no severity, the CVSS score and Debian tracker state of each CVE it links to, cached for 7 days | None |
| OSV bulk archives | `https://osv-vulnerabilities.storage.googleapis.com/all.zip`, or `https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip` for one ecosystem | _(none — full download during `db update` or `--auto-update-db`; the GitHub Action reads the per-ecosystem archives unless `vuln-db-scope: full`)_ | Advisory archives | None |
| NVD/NIST | `https://services.nvd.nist.gov/rest/json/cves/2.0` | CVE IDs, or a `lastModStartDate`/`lastModEndDate` time window during `db update --source nvd` | CVE records: CVSS scores, CWE IDs, CPE applicability ranges | Optional (NVD_API_KEY for higher rate limits, sent only as the `apiKey` header) |
| FIRST EPSS | `https://api.first.org/data/v1/epss` | CVE IDs | Exploit probability scores | None |
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | _(none — full download)_ | KEV catalog | None |
| npm registry | `https://registry.npmjs.org/{pkg}/{version}` | Package name + version | Package metadata | None |
| PyPI | `https://pypi.org/pypi/{pkg}/{version}/json` | Package name + version | Package metadata | None |
| OpenSSF Scorecard | `https://api.securityscorecards.dev/projects/github.com/{owner}/{repo}` | GitHub owner/repo | Scorecard scores | None |
| GitHub Security Advisories | `https://api.github.com/advisories` | Package names, or a time window during `db update --source ghsa` | Advisories | Optional (`GITHUB_TOKEN` or `GH_TOKEN`, sent only here) |
| deps.dev | `https://api.deps.dev/` | Package name + version | License and project metadata | None |
| Go module proxy and checksum database | `https://proxy.golang.org/`, `https://sum.golang.org/` | Module path + version | Module versions, checksums | None |
| EPSS bulk feed | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` (older address `epss.cyentia.com`, followed only as a redirect) | _(none — full download during `db update` or an advisory lookup)_ | EPSS scores | None |
| Alpine security database | `https://secdb.alpinelinux.org` | _(none — full download during `db update`)_ | Alpine advisories | None |
| Debian security tracker | `https://security-tracker.debian.org/tracker/data/json` | _(none — full download during `db update`)_ | Debian advisories | None |
| Debian extended LTS tracker | `https://deb.freexian.com/extended-lts/tracker/data/json` | _(none — full download during `db update`)_ | Debian ELTS advisories | None |
| Package downloads for the plugin launchers | `https://files.pythonhosted.org/`, `https://github.com/` (a managed Python, or a repository you name) | Package file requests | The pinned release and locked dependencies | None |

`src/agent_bom/core/egress_hosts.py` is the list the plugin READMEs are checked against.

The control plane's KEV catalog sync adds no destination. It reads the catalog that
`agent-bom db update` and a scan's KEV join already downloaded from the CISA URL
above; its cleanup tick makes no request.

## Explicit Push, Export, and Integration Destinations

The destinations below are not hidden telemetry. They are only used when an
operator configures the corresponding flag, URL, token, connector, or control
plane setting.

| Destination | Example URL | What we send | Auth |
|-------------|-------------|--------------|------|
| Push API / control plane | User-provided `--push-url` or API base URL | Sanitized findings, inventory, graph, or audit payloads | API key or bearer token |
| Webhook outbox | User-provided webhook URL | Signed posture events and delivery metadata | Operator-provided secret/token |
| SIEM / audit export | User-provided export destination or `/v1/audit/export` consumer | OCSF-shaped audit events | Deployment-specific |
| OTLP / Prometheus Pushgateway | User-provided collector endpoint | Metrics/traces, no credential values | Deployment-specific |
| Jira (optional) | `https://{instance}.atlassian.net/rest/api/3/issue` | Finding summaries | API token (`--jira-token`) |
| Slack (optional) | User-provided webhook URL | Finding summaries | Webhook URL (`--slack-webhook`) |
| Vanta (optional) | `https://api.vanta.com/v1/` | Compliance evidence | API token (`--vanta-token`) |
| Drata (optional) | `https://public-api.drata.com/` | Compliance evidence | API token (`--drata-token`) |
| SaaS connectors | Connector-specific API URL | Connector evidence requested by the operator | Connector-specific token |
| AI enrichment | Operator-provided LLM endpoint. Off by default; anything off the loopback interface also needs `AGENT_BOM_AI_ALLOW_REMOTE=1` | Redacted, bounded finding fields listed in `docs/AI_ENRICHMENT.md` | Operator-provided key |

### Data flow

```
[Local config files]  →  extract server name, command, args, env var NAMES
                          ↓
[Package names+versions]  →  sent to OSV.dev, NVD, EPSS, KEV, npm, PyPI, OpenSSF Scorecard
                          ↓
[Findings (optional)]     →  sent to configured push/export/integration destinations
                          ↓
[CVE results]  →  returned to local process, written to stdout or --output file
```

- **Sent to scanner/enrichment APIs**: package name + version, CVE ID, or repository coordinate only
- **Returned from APIs**: CVE IDs, severity scores, advisory URLs
- **Never sent to public scanner/enrichment APIs**: file paths, config contents, env var values, scan results, hostnames, IP addresses
- **Sent to configured destinations**: only the sanitized payload for the explicit push, export, connector, or webhook action the operator enabled

All external calls can be completely disabled with `--no-scan` (inventory-only mode).

**No hidden telemetry, analytics, or tracking.** Network calls occur only for
requested scanner/enrichment lookups or explicitly configured push, export,
connector, webhook, metrics, trace, or AI-enrichment destinations.

---

## Credential Handling

Credential values from MCP server configs are **never stored or shown**. At
parse time each environment variable is classified: a credential-like key name
(e.g. `OPENAI_API_KEY`, `DATABASE_URL`) or a value matching a credential,
base64 or high-entropy pattern is replaced with `***REDACTED***` before anything
is kept. Non-sensitive values (e.g. `LOG_LEVEL=debug`) are kept as-is.

When you explicitly scan project files for hardcoded secrets or PII, agent-bom
must read the files inside the requested scan scope to classify the risk. The
report still does not store the matched value or a prefix of it. Secret-scan
findings retain only:

- relative file path
- line number
- finding type and severity
- redacted evidence label such as `[CREDENTIAL_REDACTED]`
- relevant actor, tenant, device, agent, resource, and attack-path metadata

agent-bom does not validate leaked credentials, call provider APIs with them,
or transmit the matched value. Validation of whether a secret is live belongs
in a separate, explicit, operator-approved workflow.

agent-bom itself optionally uses two env vars when refreshing the local database:
- `NVD_API_KEY` — increases NVD rate limit from 5 to 50 requests per 30 seconds and widens the `db update --source nvd` window from 14 to 120 days. This key is sent only to `services.nvd.nist.gov`, only in the `apiKey` request header (never a URL), and is never logged, cached, or transmitted elsewhere.
- `GITHUB_TOKEN` — raises the GitHub Security Advisories rate limit for `db update --source ghsa` from 60 to 5,000 requests per hour. It is sent only to `api.github.com` and needs no scopes beyond public read (`contents: read` in Actions).

Neither is required, and neither is ever written to the database, reports or logs.

### Where the keys live

- **This project's CI.** `NVD_API_KEY` is an environment secret in the GitHub `release` environment, which only `main` and `v*` tags can use. Only scheduled or manually dispatched jobs that run `agent-bom db update` declare that environment, and the key is passed only to that step; no pull-request job can read it. `GITHUB_TOKEN` is the workflow's own short-lived `github.token`, passed to the same step, with the job limited to `contents: read`.
- **Self-hosted deployments.** Bring your own key. Export `NVD_API_KEY` (and optionally `GITHUB_TOKEN`) in the environment of whatever runs `agent-bom db update`, pass it through docker-compose or your Railway service variables, or, on Kubernetes, point the Helm value `nvdApiKey.existingSecret` at an existing Secret; the chart reads it with `secretKeyRef` and has no plaintext value.
- **The agent-bom GitHub Action.** Store the key as a repository or environment secret and pass `nvd-api-key: ${{ secrets.NVD_API_KEY }}`. The Action sets it only as the `NVD_API_KEY` environment variable of its scan step (the step that refreshes the database) and never writes it into a script or log line.
- **A workstation.** Keep the key in the OS keychain rather than a shell profile and export it only for the command that needs it, for example on macOS `NVD_API_KEY="$(security find-generic-password -s nvd-api-key -w)" agent-bom db update --source nvd`. agent-bom does not read the keychain itself.

---

## User Control Over Scope

Users can restrict or bypass auto-discovery entirely:

| Flag | Effect |
|------|--------|
| `--dry-run` | Shows exactly which files, APIs, and data would be accessed, then exits without reading anything |
| `--inventory <file>` | Reads agents/packages from a JSON inventory file |
| `--inventory-only` / `--no-discover` | Uses only explicit input artifacts and suppresses ambient project, cwd, skill, model, dataset, and secret discovery |
| `--project <dir>` | Restricts discovery to MCP configs in a specific project directory (does not include machine-wide configs) |
| `--config-dir <dir>` | Reads MCP configs from a single custom directory only |
| `--no-skill` | Disables skill/instruction file scanning |
| `--skill-only` | Runs only skill scanning, skips all agent/package/CVE analysis |
| `--no-scan` | Inventory-only mode — discovers configs but makes no network calls |

**Recommended first run**: `agent-bom agents --dry-run` to preview the complete access plan before any actual scanning.

---

## Verifying Our Claims

This is an open-source tool — you can verify every claim above:

| Verification | How |
|---|---|
| Read source code | `src/agent_bom/` — all scanning logic is in plain Python |
| Audit scanner/enrichment calls | `grep -rn "osv.dev\|nvd.nist\|first.org\|cisa.gov\|npmjs.org\|pypi.org" src/agent_bom/` — public vulnerability and package metadata lookups used by scanner/enrichment paths |
| Audit file access | `grep -rn "open(\|Path(" src/agent_bom/discovery/` — all file reads in the discovery module |
| Audit credential handling | `src/agent_bom/constants.py` — canonical `is_credential_key` predicate; `src/agent_bom/models.py` — `MCPServer.credential_names`; `src/agent_bom/security.py` — conservative value redaction |
| Inspect boundary contract | `agent-bom trust --format json` — code-generated data, network, storage, auth, and SCIM boundaries surfaced through CLI/API/UI |
| Verify SCIM tenant boundary | `docs/SCIM_SECURITY_MODEL.md` and `/v1/auth/policy` — tenant comes from `AGENT_BOM_SCIM_TENANT_ID`, not IdP payload fields |
| Run in isolation | `--no-scan` skips all network calls; `--dry-run` reads nothing |
| Verify signed releases | `cosign verify-blob dist/agent_bom-*.whl --bundle dist/agent_bom-*.whl.sigstore.json --certificate-oidc-issuer https://token.actions.githubusercontent.com` |
| OpenSSF Scorecard | [![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/koda-ai-studio/agent-bom/badge)](https://securityscorecards.dev/viewer/?uri=github.com/koda-ai-studio/agent-bom) |

---

## Removing a Permission

Removing a read permission never marks anything deleted. An AWS inventory with a
missing permission, a warning or a failed region proves nothing, so findings on
its assets stay open and age to stale. See
[Deleted assets](FINDING_LIFECYCLE.md#deleted-assets).

## Least Privilege — API Server

When running `agent-bom api`, the HTTP server adds these headers to every response:

```
X-Agent-Bom-Read-Only: true
X-Agent-Bom-No-Credential-Storage: true
```

These headers describe the scan surface. The API still writes its own
tenant-scoped store, and admins can trigger the opt-in side-scan; see
[SECURITY.md](../SECURITY.md#trust-model-and-permissions).

The API server itself runs entirely in-process. It does not make third-party outbound
connections unless a scan job explicitly requests enrichment (`"enrich": true` in the
request body) or an operator configures a connector, export, ticketing, webhook, or
side-scan action. Browser clients and local dashboards may still connect to the local
agent-bom API over HTTP/WebSocket for normal UI operation.

---

## Authentication Model — Zero-Credential, Zero-Trust

Local scanning does not persist credential values in reports. Provider SDKs
use credentials to authenticate, and configured control-plane connections
can retain encrypted credentials. Inventory collection uses read-only scopes.
Opt-in disk side-scans use a separate lifecycle role; event consumers also
acknowledge queue messages as described below (see
[SECURITY.md](../SECURITY.md#trust-model-and-permissions)).

### How auth works per provider

| Provider | Preferred auth | Fallback | What we read |
|----------|---------------|----------|--------------|
| **Snowflake** | SSO via `externalbrowser` (Okta/Azure AD/Google) — default | Key-pair (`SNOWFLAKE_PRIVATE_KEY_PATH`) for CI/CD | Read-only SQL on ACCOUNT_USAGE |
| **Databricks** | SDK credential chain: `~/.databrickscfg` OAuth profile or workload identity | `DATABRICKS_TOKEN` PAT env | Read-only cluster/library listing |
| **AWS** | IAM role / OIDC workload identity (GitHub Actions) / `~/.aws/credentials` profile | `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` env | Read-only: `Describe*`, `List*`, `Get*` |
| **Azure** | Managed identity / `az login` / service principal | `AZURE_CLIENT_SECRET` env | Read-only resource listing |
| **GCP** | Application Default Credentials / workload identity | `GOOGLE_APPLICATION_CREDENTIALS` env | Read-only resource listing |
| **HuggingFace** | `HF_TOKEN` env (read-only scope) — optional, public models need nothing | None | Model metadata via Hub API |
| **NVD** | `NVD_API_KEY` env — optional, only increases rate limits | None (public API) | CVE data only |

### Snowflake — explicit auth options

```bash
# Preferred: SSO (default — opens browser for Okta/Azure AD/Google)
agent-bom agents --snowflake

# Key-pair auth (recommended for CI/CD — no browser needed)
SNOWFLAKE_PRIVATE_KEY_PATH=~/.ssh/snowflake_key.p8 \
agent-bom agents --snowflake

# Explicit SSO
agent-bom agents --snowflake --snowflake-authenticator externalbrowser

# OAuth access token
SNOWFLAKE_AUTHENTICATOR=oauth SNOWFLAKE_TOKEN=<token> \
agent-bom agents --snowflake

# OAuth token
SNOWFLAKE_TOKEN=<token> \
agent-bom agents --snowflake --snowflake-authenticator oauth
```

### CIA Triad compliance

| Principle | How agent-bom upholds it |
|-----------|--------------------------|
| **Confidentiality** | Credentials pass env → SDK, never logged. `sanitize_error()` strips secrets from all error messages. Audit logs stored at `0600` permissions. |
| **Integrity** | SHA-256 payload hashing on every proxied MCP call. Audit logs HMAC-signed (SHA-256) for tamper detection. Set `AGENT_BOM_AUDIT_HMAC_KEY` in production to persist verifiability across restarts; production or multi-replica control planes fail closed without it unless `AGENT_BOM_ALLOW_EPHEMERAL_AUDIT_HMAC=1` is explicitly set. Model weight hash verification (`agent-bom verify --model-dir ...` or `--verify-model-hashes` in scan workflows). SBOM + VEX support for supply chain integrity. |
| **Availability** | Graceful degradation on auth failure (warning, not crash). Offline mode (`--no-scan`). Rate limiting respected — we never exhaust API quotas. |

### What we never do

- Ordinary inventory scans do not mutate cloud resources. Explicit disk
  side-scans and configured event consumers have the bounded write permissions
  described here.
- Local scanning does not cache credential values; configured control-plane
  connections use the documented encrypted credential store.
- Never log credential values (sanitize_error removes them)
- Never require admin/write permissions for scanning
- Never make third-party network calls beyond the explicitly listed data sources.
  Local UI-to-API traffic is expected when using the dashboard or browser client.

---

## AI advice routes

| Route | Minimum role | Scope | Calls a model |
|---|---|---|---|
| `GET /v1/findings` (`ai_assessment` on each row) | viewer | existing finding scope | No |
| `GET /v1/ai/status` | viewer | `ai:read` | No |
| `POST /v1/graph/explain` | analyst | `ai:invoke` | Yes, once per request, within the tenant's rate and daily budget |

Every query names the tenant, and both advice tables enforce row-level security.
`AGENT_BOM_AI_CONTROL_PLANE_ENABLED` turns hosted use on,
`AGENT_BOM_AI_CONTROL_PLANE_TENANTS` narrows it to listed tenants, and
`AGENT_BOM_AI_CONTROL_PLANE_MODEL` fixes the model so a request cannot choose one.

### Local AI call log

`agent-bom scan --ai-enrich` appends one record per model call to
`<state dir>/ai-audit/ai-calls.jsonl` (mode 0600), with a `.chain-key` file beside it.
The state directory is `AGENT_BOM_STATE_DIR` or the product default. Records hold the
same fields as the control plane's `ai.call` audit entries: identity, hashes, counts
and outcome, never prompt or response text. Check it with
`agent-bom runtime audit <path> --verify-chain`. Set `AGENT_BOM_AI_LOCAL_AUDIT=0` to
opt out. Set `AGENT_BOM_AUDIT_HMAC_KEY` to keep the signing key away from the log.

## Event consumer acknowledgement permissions

Configured AWS and Azure event consumers are queue workers, not ordinary
inventory reads. They receive messages and delete acknowledged messages from
the operator-configured queue:

- AWS: grant `sqs:ReceiveMessage` and `sqs:DeleteMessage` only on the dedicated
  queue. The consumer identity is separate from the brokered read-only customer
  session used for the resulting scan.
- Azure: the Storage Queue client needs message receive/process permission,
  including message deletion, scoped to the dedicated queue. Its credential is
  separate from the brokered subscription inventory credential.

Successful dispatch is acknowledged. Dispatch failures stay on the queue for
redelivery after the visibility timeout. Malformed messages and messages for a
different account/subscription are also deleted, with summary counters; their
original bodies are not retained by these consumers. Use a dedicated queue per
connection and retain source CloudTrail/Event Grid evidence independently if
replay or investigation retention is required. A failed acknowledgement makes
the pass partial; it is not evidence that the queue was drained.

Implementation: `cloud/event_ingest.py` and `cloud/azure_event_ingest.py`.

## Browser documentation assets

When enabled, `/docs` and `/redoc` load pinned Swagger UI/ReDoc files from
`cdn.jsdelivr.net` with SHA-384 subresource integrity and fresh script nonces.
The browser makes these asset requests; the API does not download code at
startup. Inline styles remain permitted for those renderers. Set
`AGENT_BOM_DISABLE_DOCS=1` to remove the documentation and schema routes from a
production deployment.

## Reporting a Security Issue

See [SECURITY.md](../SECURITY.md) for responsible disclosure via GitHub Security Advisories.

## Explicit lake snapshot ingestion

`agent-bom ingest lake` reads the selected local JSON/NDJSON file and mapping.
For an explicit `s3://` input it uses the AWS SDK credential chain to perform
`GetObject` for the required object version and expected bucket owner. It never
lists buckets, subscribes to events, executes lake queries or writes to S3.
Grant `s3:GetObjectVersion` on the selected object and applicable KMS decrypt
permission for encrypted objects. Inputs are capped at 16 MiB / 1,000 findings.
Only mapped fields enter the retained private report.

`--push` sends that report only to the explicitly configured control plane,
using `AGENT_BOM_PUSH_API_KEY` and the existing outbound URL/sanitization policy.
Without `--push`, no report is sent. Source collection completeness remains
unknown; imports do not resolve absent findings or prove exploitability.
See [lake ingestion](../site-docs/deployment/lake-evidence-ingestion.md).

## Plugin hook and tool hints

`agent-bom-guard` runs one Claude Code `PreToolUse` hook on the Bash tool. Claude Code
passes it each Bash command as text; it finds package installs in that text without
running anything, stores nothing, and sends only package name, ecosystem and pinned
version to `api.osv.dev` (a private package name included, unless `osv_lookup` is off).
Its [README](../integrations/agent-bom-guard/README.md) has the full contract.

The tool hints in the two plugin profiles match what the tools do:

| Tools | `readOnlyHint` | `openWorldHint` | Why |
|-------|----------------|-----------------|-----|
| `scan` | false | true | Keeps a redacted result under `~/.agent-bom` for a later page, and `auto_update_db` refreshes the local advisory database. Its target is unchanged, so `destructiveHint` is false. |
| `check`, `intel_lookup`, `policy_check`, `compliance`, `generate_sbom`, `remediate` | true | true | Look up advisories or run a scan without keeping a result; lookup caches are the only local writes. |
| `inventory`, `skill_scan`, `skill_trust`, `prompt_scan`, `audit_integrity`, `exposure_paths`, `executive_brief` | true | false | Read local files or the local store and open no socket; `exposure_paths` and `executive_brief` rebuild a derived cache under `~/.agent-bom`. |
| `tool_risk_assessment` | false | true | `live=true` can contact or launch a server, so `destructiveHint` is true. The plugins start it with `AGENT_BOM_MCP_LIVE_INTROSPECTION=0`, which refuses that. |

## Directory and hosted OAuth boundaries

The directory skills and `audit` MCP profile exclude `agent_activity` and chat
history review. The standalone full compatibility profile remains a separate
operator-selected surface. Directory pins must reference a release containing
this exclusion before submission; updating skill files does not change an
already published executable.

OAuth MCP deployments expose only tools that leave target systems unchanged,
excluding process launching and history inspection. `scan` is among them and can
retain redacted results in the tenant/caller-bound result store, so it reports
`readOnlyHint: false`.
Its default readable TTL is 1,800 seconds and its default bound is four rows per
tenant; expired rows are deleted during subsequent writes, not by a guaranteed
wall-clock deletion job. Token rotation deliberately loses access to the prior
token's cached results. Local report files, persisted graph/audit evidence,
backups and external hosting logs have separate operator-controlled retention.
Recent MCP request traces are in-memory and bounded to 256 entries by default.

The external authorization server owns login, consent, client registration and
refresh-token storage/rotation. The MCP service checks signatures, issuer,
audience, approved subject, time limits, `read` scope and an exact signed
`tenant_id` matching the explicitly configured deployment tenant. An untrusted
tenant header or tool argument cannot move a request to another tenant.

The configured issuer is the sole OAuth network destination: public JWKS GETs
and authenticated RFC 7662 introspection POSTs to that same HTTPS origin.
Introspection sends the presented access token and confidential resource-client
credentials to its intended issuer, not to a tool, package service or new
telemetry destination. Responses are bounded to 256 KiB, requests time out after
five seconds, redirects are refused and TLS is verified. The service never
issues OAuth tokens or receives a password-login form submission. Issuer and
hosting retention must be documented by the service owner.

See [MCP OAuth setup](MCP_OAUTH.md) and the
[OAuth failure modes and STRIDE assessment](RUNTIME_FAIL_MODES.md#hosted-mcp-oauth).
The draft [privacy](../site-docs/privacy.md) and [terms](../site-docs/terms.md)
pages require owner review before publication; they make no certification claim.
