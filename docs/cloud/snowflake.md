# Snowflake connection reference

Use this guide for the provider grant, collected evidence and coverage limits.
Return to [cloud connections](../CLOUD_CONNECT.md) for shared onboarding.

## 6. Snowflake — connect with a key-pair, never a password

**Grant** (read-only role + key-pair user). Run once as `ACCOUNTADMIN`:

```sql
USE ROLE ACCOUNTADMIN;
CREATE ROLE IF NOT EXISTS ABOM_READONLY;

-- ACCOUNT_USAGE powers inventory + the CIS benchmark
GRANT IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE TO ROLE ABOM_READONLY;
-- Account usage visibility; object-specific SHOW visibility still follows grants.
GRANT MONITOR USAGE ON ACCOUNT TO ROLE ABOM_READONLY;
GRANT USAGE ON WAREHOUSE COMPUTE_WH TO ROLE ABOM_READONLY;   -- swap to your WH

-- key-pair scanner user (no password)
CREATE USER IF NOT EXISTS ABOM_SCANNER
  DEFAULT_ROLE = ABOM_READONLY
  DEFAULT_WAREHOUSE = 'COMPUTE_WH'
  RSA_PUBLIC_KEY = '<PEM public key, no headers>';
GRANT ROLE ABOM_READONLY TO USER ABOM_SCANNER;
```

**Why each grant — mapped to what it unlocks:**

| Grant | Unlocks |
|-------|---------|
| `IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE` | Shared Snowflake metadata and history, including available `ACCOUNT_USAGE` views. Does not grant access to customer tables or every customer database’s `INFORMATION_SCHEMA`. |
| `MONITOR USAGE ON ACCOUNT` | Account usage visibility. Does not make every object visible to `SHOW` commands. |
| `USAGE ON WAREHOUSE` | the compute to run the read-only `SELECT`s |

Validate each enabled collection lane with the scanner role. `SHOW GRANTS` and
customer `INFORMATION_SCHEMA` views respect the role’s object visibility;
additional metadata visibility must be scoped to the intended objects. A
successful connection or empty result does not establish account-wide coverage.
Do not add `MANAGE GRANTS` to this read-only role: that privilege can change
access, even though it also expands visibility. See [SHOW GRANTS visibility](https://docs.snowflake.com/en/sql-reference/sql/show-grants#usage-notes)
and [Information Schema visibility](https://docs.snowflake.com/en/sql-reference/info-schema#general-usage-notes).

`ACCOUNT_USAGE.GRANTS_TO_ROLES` can lag by up to two hours. A collected grant is
recorded metadata, not a fresh session authorization decision; an empty,
visibility-limited `SHOW` response cannot by itself prove revocation. Review
collection warnings and source freshness before using the graph to assess a
change. See [grant-view limits](https://docs.snowflake.com/en/sql-reference/account-usage/grants_to_roles#usage-notes).

Cortex agent inventory, user-role membership and object grants are separate
pieces of evidence. They do not establish which session and primary or secondary
roles an agent used. Access-history collection joins query IDs to recorded
users and role names, but the current collector does not ingest the agent chain
in `agents_info` or evaluate all session and data-policy conditions. Confirm
exact agent attribution with the corresponding runtime records before claiming
agent-specific read/write access. See [ACCESS_HISTORY fields](https://docs.snowflake.com/en/sql-reference/account-usage/access_history#columns).

**Cortex Agents (optional, per agent).** To model an agent's declared tools,
execution roles and runtime spans, the scanner role needs, for each agent it
should cover:

```sql
GRANT USAGE ON DATABASE <db> TO ROLE ABOM_READONLY;
GRANT USAGE ON SCHEMA <db>.<schema> TO ROLE ABOM_READONLY;
GRANT MONITOR ON AGENT <db>.<schema>.<agent> TO ROLE ABOM_READONLY;  -- SHOW/DESCRIBE AGENT, observability events
GRANT DATABASE ROLE SNOWFLAKE.CORTEX_USER TO ROLE ABOM_READONLY;     -- GET_AI_OBSERVABILITY_EVENTS
```

| Read | Used for |
|------|----------|
| `SHOW AGENTS IN ACCOUNT`, `DESCRIBE AGENT` | the agent specification: only the tools it declares (`tools` / `tool_resources`) and the objects they name are attached to the agent |
| `SHOW GRANTS ON AGENT` | roles holding `USAGE` or `OWNERSHIP` on the agent |
| `SNOWFLAKE.LOCAL.GET_AI_OBSERVABILITY_EVENTS(<db>, <schema>, <agent>, 'CORTEX AGENT')` | span metadata aggregated into runtime-observed agent → tool / warehouse / role edges |

Roles granted `USAGE` or `OWNERSHIP` describe access to the agent; these
grants alone do not identify the execution role of a particular invocation.
Inspect session and runtime evidence before attributing downstream access.
`DESCRIBE AGENT` returns no specification for a secure agent unless the owner
role is active, so such agents show `spec_status: hidden` and no tools. Do not
grant `READ UNREDACTED AI OBSERVABILITY EVENTS TABLE`: the collector keeps only
tool names, timings, token counts and a SHA-256 digest of span content. It
stores no user name or plain hash of one, and never prompts or tool
inputs/outputs.
See [DESCRIBE AGENT](https://docs.snowflake.com/en/sql-reference/sql/desc-agent),
[Cortex Agents access control](https://docs.snowflake.com/en/user-guide/snowflake-cortex/cortex-agents)
and [GET_AI_OBSERVABILITY_EVENTS](https://docs.snowflake.com/en/sql-reference/functions/get_ai_observability_events-snowflake-local).

**Authenticate** with the matching private key — no password ever:

```bash
export SNOWFLAKE_ACCOUNT="ORG-ACCOUNT"      # or LOCATOR.region.cloud, e.g. xy12345.ca-central-1.aws
export SNOWFLAKE_USER="ABOM_SCANNER"
export SNOWFLAKE_AUTHENTICATOR="snowflake_jwt"
export SNOWFLAKE_PRIVATE_KEY_PATH="/path/to/abom_key.p8"
agent-bom agents --snowflake
```

**Why key-pair over password:** key-pair (RSA JWT) means no shared secret ever
transits or is stored; the private key stays on the scanner host. Password auth
is deprecated in the connector and emits a runtime warning. SSO
(`externalbrowser`) and OAuth are also supported for interactive use.

**What it reads:** the **AI-BOM** (Cortex agents, MCP servers, Snowpark
packages, UDFs/procedures, notebooks, Streamlit apps); the object + lineage
graph (tables/views + `OBJECT_DEPENDENCIES`, grants, role memberships); data-exit
surface (outbound shares, external stages, sensitivity-tagged objects); per-user
auth posture (MFA / key-pair / password, network policies); login anomalies
(impossible travel, IP spread, failed-login bursts); warehouses/databases/schemas;
pipeline objects (tasks/streams/pipes); account integrations; iceberg/external
tables; and **14 CIS checks**.

**Honest caveats (accuracy):** `ACCOUNT_USAGE` views have ingestion latency
(minutes to hours), so freshly-created objects and tags may lag one scan.
Discoveries that need a grant you didn't give degrade to empty rather than error
— so apply the full grant block above for complete coverage.

---

## ❄️ Snowflake Integration

> **Note**: agent-bom integrates with Snowflake for **scanning Cortex Agents,
> CoCo skills, Snowpark resources, and Snowflake-hosted app surfaces**.
> The primary shipped web UI remains the packaged Next.js dashboard. The
> Streamlit path below is a Snowflake-specific compatibility / native-view
> option, not the default product dashboard.

### Reference Architecture

```
              Snowflake Account
┌─────────────────────────────────────┐
│  Snowpark Container Service         │
│  ┌─────────────────┐                │
│  │ agent-bom API   │─writes─► Tables│
│  │ (port 8422)     │                │
│  └─────────────────┘                │
│                                     │
│  Streamlit in Snowflake             │
│  ┌─────────────────┐                │
│  │ SiS Dashboard   │─reads──► Tables│
│  └─────────────────┘                │
└─────────────────────────────────────┘
```

### Quick Start

1. **Run setup SQL** — creates database, tables, image repo, compute pool, and service:
   ```bash
   snowsql -f deploy/snowflake/setup.sql
   ```

2. **Build and push the container image**:
   ```bash
   docker build -f deploy/docker/Dockerfile.snowpark -t agent-bom-snowpark:latest .
   docker tag agent-bom-snowpark:latest \
     <account>.registry.snowflakecomputing.com/agent_bom/public/agent_bom_repo/agent-bom:latest
   docker push <account>.registry.snowflakecomputing.com/agent_bom/public/agent_bom_repo/agent-bom:latest
   ```

   Enterprise networks can use the same proxy and custom-CA contract as the other maintained images:
   `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, and `PIP_CERT`.

3. **Optional: deploy the Snowflake-native Streamlit view** — upload `deploy/snowflake/streamlit_app.py` and `deploy/snowflake/environment.yml` via the Snowflake web UI (Streamlit > + Streamlit App).

### Authentication

Snowflake job-store reads, deletes and summary listings require an explicit
`tenant_id`. Omitted scope fails before opening a database connection. Trusted
background reconciliation must explicitly request `all_tenants=True`; the
configured Snowflake row-access policy remains in force. Older binaries retain
the prior behavior, so keep request-serving instances on the corrected version.

The Snowflake stores auto-detect auth method:

| Env Var | Method |
|---------|--------|
| `SNOWFLAKE_PRIVATE_KEY_PATH` | Key-pair auth (preferred for CI/CD and service accounts) |
| `SNOWFLAKE_AUTHENTICATOR` | Auth method: `externalbrowser` (SSO, default), `oauth`, `snowflake_jwt` |
| `SNOWFLAKE_PASSWORD` | **Deprecated** — emits warning. Migrate to key-pair or SSO |

Additional env vars: `SNOWFLAKE_ACCOUNT`, `SNOWFLAKE_USER`, `SNOWFLAKE_DATABASE` (default: `AGENT_BOM`), `SNOWFLAKE_SCHEMA` (default: `PUBLIC`).

### Tables

| Table | Purpose |
|-------|---------|
| `scan_jobs` | Scan job persistence (status, results as VARIANT) |
| `fleet_agents` | Fleet agent lifecycle (trust scores, states) |
| `fleet_endpoints` | Latest privacy-safe workstation sweep summary per tenant/source ID |
| `gateway_policies` | Runtime MCP gateway policies |
| `policy_audit_log` | Policy enforcement audit trail |

---
