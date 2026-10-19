# Python API

`agent-bom` exposes a small public Python API for tools that want typed scan
results without shelling out to the CLI, plus a typed control-plane client for
stable REST endpoints. These surfaces are wrappers over shipped scanner,
inventory, diff, and API primitives; they are not parallel implementations.

## Install

```bash
pip install agent-bom
```

Use the API extra when the same environment also starts a local control plane:

```bash
pip install 'agent-bom[api]'
```

## Local Scan Helpers

```python
from agent_bom import check, diff, scan
from agent_bom.sdk import inventory

report = scan(project=".", offline=True)
for finding in report.to_findings():
    print(finding.id, finding.severity)

package = check("requests@2.31.0", ecosystem="pypi", offline=True)
print(package.status, package.vulnerabilities)

fleet = inventory("fleet-inventory.json")
print(fleet.agent_count, fleet.package_count)

delta = diff("baseline.json", "current.json")
print(delta.summary)
```

## Control-Plane Client

Use `AgentBomClient` from services, notebooks, and automation that already have
an agent-bom API URL and token. The client keeps auth and tenant headers in one
place and exposes stable evidence endpoints without requiring callers to build
URLs manually.

```python
from agent_bom import AgentBomClient

with AgentBomClient(
    base_url="https://agent-bom.internal",
    api_key="agent-bom-api-key",
    tenant_id="tenant-a",
) as client:
    print(client.health()["status"])
    manifest = client.agent_manifest()
    runtime = client.runtime_production_index()
    intel = client.intel_sources()
    decision = client.should_i_deploy("flask@2.0.0", block_risk=80)

print(manifest["schema_version"], runtime["schema_version"], len(intel.get("sources", [])), decision["decision"])
```

For a smoke test against a running API:

```bash
AGENT_BOM_BASE_URL=http://127.0.0.1:8422 \
AGENT_BOM_API_KEY=dev-key \
python examples/python_sdk/control_plane_smoke.py
```

## Functions

| Function | Returns | Boundary |
|---|---|---|
| `scan(...)` | `agent_bom.models.AIBOMReport` | Runs the same local simple scan runner used by CLI scan-consuming commands. |
| `check(...)` | `PackageCheckResult` | Synchronous single-package vulnerability check. |
| `async_check(...)` | `PackageCheckResult` | Async single-package vulnerability check for applications already running an event loop. |
| `agent_bom.sdk.inventory(...)` | `InventoryResult` | Parses JSON, CSV, or NDJSON inventory using the canonical inventory loader. Kept under `agent_bom.sdk` to avoid shadowing the existing `agent_bom.inventory` module. |
| `diff(...)` | `DiffResult` | Diffs two agent-bom reports or SBOM documents using the history diff engine. |

## Inventory identity

`GET /v1/inventory` returns package occurrences with `agent_id`, `server_id`,
and `environment`. Equal display names do not merge different occurrences;
missing identity stays empty and distinct records remain separate. Its existing
`limit` and `offset` apply to each returned collection, with separate totals.

`GET /v1/agent-bom/manifest` counts identified MCP servers once and retains
their `agent_names`, `observation_ids`, and sanitized `observations`. Multiple
reported agents do not imply one shared owner or environment. Conflicting
server identities stay observation-scoped and do not acquire graph membership
through a display-name fallback. The manifest remains a complete tenant-scoped
export, rather than a paginated collection.

## Client Methods

| Method | Endpoint | Use |
|---|---|---|
| `health()` | `GET /health` | API liveness and configured subsystem health. |
| `agent_manifest()` | `GET /v1/agent-bom/manifest` | Tenant-scoped agent, MCP server, tool, and credential-reference posture. |
| `runtime_production_index()` | `GET /v1/runtime/production-index` | Runtime traffic, policy, freshness, alert, and retention posture. |
| `ingest_runtime_events(...)` | `POST /v1/runtime/events` | Metadata-only runtime event ingest for session and tool-call observability. |
| `runtime_sessions(...)` | `GET /v1/runtime/sessions` | Tenant-scoped runtime sessions with event, verdict, severity, and tool summaries. |
| `runtime_observations(...)` | `GET /v1/runtime/observations` | Tenant-scoped metadata-only runtime observations with optional session filtering. |
| `runtime_session_observations(...)` | `GET /v1/runtime/sessions/{session_id}/observations` | Observations for one runtime session. |
| `exposure_paths()` | `GET /v1/graph/exposure-paths` | Graph-backed reachability and blast-radius paths. |
| `should_i_deploy(...)` | `POST /v1/graph/should-i-deploy` | Allow/warn/block deployment guidance from graph risk. |
| `list_findings(...)` | `GET /v1/findings` | Normalized findings with severity and pagination filters. |
| `ingest_findings(...)` | `POST /v1/findings/bulk` | Bulk finding ingest from external scanners or jobs. |
| `register_dataset_version(...)` | `POST /v1/datasets/{dataset_id}/versions` | Dataset artifact evidence registration. |
| `register_evaluation_run(...)` | `POST /v1/evaluations` | Evaluation run evidence linked to dataset versions, traces, models, and prompt hashes. |
| `evaluation_runs(...)` | `GET /v1/evaluations` | Tenant-scoped evaluation run listing with dataset filters. |
| `evaluation_run(...)` | `GET /v1/evaluations/{evaluation_id}` | One evaluation run record. |
| `intel_lookup(...)` | `GET /v1/intel/advisories/{advisory_id}` | Advisory lookup by CVE, GHSA, or OSV ID. |
| `intel_match(...)` | `POST /v1/intel/match` | Match package coordinates against local advisory intelligence. |
| `intel_sources()` | `GET /v1/intel/sources` | Source registry and freshness metadata. |

Common write and governance calls keep the payload in the first positional
argument:

```python
client.ingest_findings(
    [{"id": "finding-1", "severity": "high", "title": "External scanner finding"}],
    source="external-scanner",
)
client.register_dataset_version("training-set", version_id="2026-05-24")
client.register_evaluation_run(
    evaluation_id="eval-2026-05-25",
    dataset_id="training-set",
    dataset_version_id="2026-05-24",
    model="gpt-4.1-mini",
    prompt_hash="sha256:...",
    scores={"safety": 1.0},
)
client.should_i_deploy("flask@2.0.0", block_risk=80)
```

## Notes

- `check()` cannot be called from an already running event loop; use
  `async_check()` in async applications.
- `scan(config_path=...)` and `scan(project=...)` both define the local scan
  scope. Passing both is allowed only when they refer to the same path.
- The returned `AIBOMReport` uses the same typed dataclasses as the rest of the
  package, including `Finding`, `Asset`, `Package`, and `BlastRadius`.
- The control-plane client accepts either `api_key` or `bearer_token`, not both.
  `tenant_id` is sent as `X-Agent-Bom-Tenant-ID` and is also used as the
  default tenant query/body value for tenant-scoped methods.

## Plugin entry points

`agent-bom` provides opt-in entry-point registration for plugin authors.
The loader imports registrations, validates bounded metadata, and reports
sanitized loading warnings. It does not execute or attach
third-party plugins to MCP, advisory, or runtime paths by default.

Third-party entry-point loading is opt-in:

```bash
AGENT_BOM_ENABLE_EXTENSION_ENTRYPOINTS=true agent-bom agents --demo --offline
```

Operators can inspect the registry without loading third-party plugin code:

```bash
agent-bom plugins status --format json
curl -H "Authorization: Bearer $AGENT_BOM_API_KEY" \
  http://localhost:8422/v1/plugins/status
```

The status contract is metadata-only. It reports built-in registration counts,
installed entry-point declarations, and whether opt-in loading is enabled.

### Supported Groups

| Group | Purpose | Default runtime behavior | Activation flag |
|---|---|---|---|
| `agent_bom.mcp_tools` | Advertise an MCP tool registration module and function. | Not registered on the live MCP server. | `AGENT_BOM_ACTIVATE_MCP_TOOL_PLUGINS` |
| `agent_bom.advisory_sources` | Advertise a private advisory lookup or sync source. | Not queried during scans. | `AGENT_BOM_ACTIVATE_ADVISORY_SOURCE_PLUGINS` |
| `agent_bom.runtime_emitters` | Advertise a runtime event emitter. | Not added to proxy, gateway, or alert dispatch. | `AGENT_BOM_ACTIVATE_RUNTIME_EMITTER_PLUGINS` |

### Runtime Activation

The status commands inspect installed entry-point metadata without importing
plugins. Enabling registration loading imports third-party code and invokes
registration factories; install and enable only trusted packages. Declared
capabilities describe the extension but do not sandbox its Python code.

Registration and activated callbacks execute inside the host interpreter with
its filesystem, network and credential access. Output-size caps and bounded
registration counts do not limit execution time, memory, subprocesses or side
effects. Use a separate, least-privileged process/container for packages that
require an isolation boundary; the entry-point loader does not provide one.

Runtime activation is a **second, explicit opt-in** on top of registration loading
for the three groups below. A group
activates only when both `AGENT_BOM_ENABLE_EXTENSION_ENTRYPOINTS` (discovery) and
that group's activation flag are set. With no activation flag set, every surface
below is a no-op and default behavior is unchanged.

```bash
# Register discovered third-party MCP tools on the live MCP server.
AGENT_BOM_ENABLE_EXTENSION_ENTRYPOINTS=true \
AGENT_BOM_ACTIVATE_MCP_TOOL_PLUGINS=true \
  agent-bom mcp

# Augment `intel lookup` with operator-owned advisory sources.
AGENT_BOM_ENABLE_EXTENSION_ENTRYPOINTS=true \
AGENT_BOM_ACTIVATE_ADVISORY_SOURCE_PLUGINS=true agent-bom ...

# Fan runtime observations out to operator-owned event emitters.
AGENT_BOM_ENABLE_EXTENSION_ENTRYPOINTS=true \
AGENT_BOM_ACTIVATE_RUNTIME_EMITTER_PLUGINS=true agent-bom serve
```

Activation surfaces, per group:

- **MCP tools** — each activated plugin's `register_attr` (default `register_tools`)
  is called with the live server during `create_mcp_server`; plugin-added tools
  are then hardened with the same strict-argument contract as built-ins.
- **Advisory sources** — the `intel lookup` MCP tool calls each activated source's
  `lookup_attr` (default `lookup`) and appends provenance-tagged records under
  `operator_advisory_sources`. The deterministic local result is never replaced.
- **Runtime emitters** — every persisted runtime observation is forwarded to each
  activated emitter's `emit_attr` (default `emit`) as a **redacted routing
  envelope** (`runtime.emitter_envelope.v1`) that carries only metadata — never
  raw prompts, tool arguments, or credential values.

Every activation is isolated: an import, binding, or invocation failure in one
plugin is sanitized into a warning and never crashes the server or scan, and one
failing plugin does not stop the others. Inspect the live wiring with:

```bash
agent-bom plugins activation --format json
```

The `agent-bom plugins status` view also reports each group's `activation_enabled`
state so operators can see what would run before enabling it.

The registry status view also includes existing built-in extension groups:
`agent_bom.cloud_providers`, `agent_bom.connectors`,
`agent_bom.inventory_parsers`, and `agent_bom.importers`.

`agent_bom.importers` registers file-based scanner report importers. Like
inventory parsers, entries load when `AGENT_BOM_ENABLE_EXTENSION_ENTRYPOINTS`
is set; they run after every built-in format and cannot replace a built-in
importer. The contract, transparency manifest and a complete example are in
[Scanner importers](IMPORTERS.md).

Each group is capped at 32 loaded entry points per process. Import, validation,
and coercion failures are non-fatal; built-in behavior remains available and
warnings are sanitized before they can leave the process.

### Author Contract

Expose a callable entry point that returns a registration object. The object may
be one of the dataclasses in `agent_bom.plugin_entrypoints` or any object with
the same public attributes.

```toml
[project.entry-points."agent_bom.advisory_sources"]
private-feed = "acme_agent_bom_advisories:registration"
```

```python
from agent_bom.extensions import ExtensionCapabilities
from agent_bom.plugin_entrypoints import AdvisorySourcePluginRegistration


def registration() -> AdvisorySourcePluginRegistration:
    return AdvisorySourcePluginRegistration(
        name="private-feed",
        module="acme_agent_bom_advisories.feed",
        lookup_attr="lookup",
        sync_attr="sync",
        capabilities=ExtensionCapabilities(
            scan_modes=("advisory_lookup",),
            required_scopes=("private_feed_read",),
            outbound_destinations=("advisories.example.internal",),
            data_boundary="customer_controlled_advisory_lookup",
            network_access=True,
        ),
        source="entry_point",
    )
```

Required fields:

- `name`: stable plugin identifier.
- `module`: import path for the implementation module.
- `capabilities`: declared permissions, outbound destinations, and data
  boundary. If omitted, agent-bom applies conservative metadata-only defaults.

Group-specific optional fields:

- `agent_bom.mcp_tools`: `register_attr`, default `register_tools`.
- `agent_bom.advisory_sources`: `lookup_attr`, default `lookup`; `sync_attr`,
  default `sync`.
- `agent_bom.runtime_emitters`: `emit_attr`, default `emit`; `flush_attr`,
  default `flush`.

### Runnable Examples

Concrete examples live in [`examples/plugin_entrypoints/`](../examples/plugin_entrypoints/):

- `example_mcp_tools.py` advertises a read-only MCP posture tool and a
  `register_tools(mcp)` function.
- `example_advisory_source.py` advertises a license-aware advisory lookup/sync
  source that returns summaries and source URLs instead of redistributing full
  advisory bodies.
- `example_runtime_emitter.py` advertises a runtime event emitter that keeps
  only redacted metadata envelopes and avoids raw prompts, arguments, and
  credential values.

These examples are covered by `tests/test_plugin_entrypoint_examples.py` so the
documented plugin contract stays importable.

### First Verification

For plugin package tests, monkeypatch `importlib.metadata.entry_points`, set
`AGENT_BOM_ENABLE_EXTENSION_ENTRYPOINTS=true`, and call:

```python
from agent_bom.plugin_entrypoints import list_advisory_source_plugins

plugins = list_advisory_source_plugins()
assert plugins[0].name == "private-feed"
```

This verifies discovery only. Runtime activation remains a separate,
operator-controlled integration step.
