# Compliance Frameworks

agent-bom maps scan findings to curated security and compliance frameworks and exposes OWASP AISVS as benchmark evidence.

**Scope:** these mappings are a curated **evidence helper** for AI/MCP/agent risk
triage. They are **not** a certification, audit opinion, attestation of
compliance, or a complete framework catalog. Operators and auditors must validate
controls against the customer environment and the exact release in use. For
procurement-oriented product evidence mapping, see `docs/CONTROL_MAPPING.md` in
the repository (not published on this docs site).

Framework catalogs are pinned in-repo by default so scans stay deterministic,
offline-friendly, and reproducible. Catalog refreshes can happen out of band;
the scan hot path does not fetch MITRE or other framework data at runtime.

## Supported frameworks

| Framework | Module | Focus |
|-----------|--------|-------|
| OWASP LLM Top 10 | `owasp.py` | LLM-specific risks |
| OWASP Agentic Security | `owasp_agentic.py` | Agent autonomy risks |
| OWASP MCP Top 10 | `owasp_mcp.py` | MCP protocol risks |
| MITRE ATLAS | `atlas.py` | Source-backed weakness associations; not scored as controls |
| EU AI Act | `eu_ai_act.py` | EU regulatory compliance |
| NIST AI RMF | `nist_ai_rmf.py` | AI risk management |
| NIST CSF | `nist_csf.py` | Cybersecurity framework |
| SOC 2 | `soc2.py` | Trust service criteria |
| ISO 27001 | `iso_27001.py` | Information security |
| CIS Controls | `cis_controls.py` | Security best practices |
| CMMC 2.0 | `cmmc.py` | Defense contractor practices |
| NIST 800-53 | `nist_800_53.py` | Federal security controls |
| FedRAMP Moderate | `fedramp.py` | Federal cloud baseline |
| PCI DSS | `pci_dss.py` | Payment data controls |

## Benchmark surfaces

MITRE ATT&CK and ATLAS are applicability overlays, excluded from control pass
rates. For package findings in AI/MCP inventory, ATLAS associations require an
advisory CWE with an explicit CWE → CAPEC → ATT&CK catalog relationship and a
matching ATLAS ATT&CK reference. Tool names, credential references, package names
and severity alone do not establish adversary techniques or observed execution.
The scan retains catalog hashes and the association chain in
`atlas_mapping_evidence`. Expand **Mapping sources** on a scan result, or inspect
the JSON/SARIF receipt and the CycloneDX/SPDX annotations. Missing associations
mean insufficient mapping evidence, not absence of risk.

| Benchmark | Module | Focus |
|-----------|--------|-------|
| OWASP AISVS v1.0 | `cloud/aisvs_benchmark.py` | AI security verification checks |

## Usage

```bash
# Single framework
agent-bom agents --compliance

# Compliance evidence export
agent-bom agents --compliance --compliance-export nist-ai-rmf
```

## Executive brief and signed evidence pack

With an authenticated control plane configured, export a leadership brief:

```bash
agent-bom report brief --api-url https://control-plane.example.com --format markdown > executive-brief.md
agent-bom report brief --api-url https://control-plane.example.com --format json > executive-brief.json
```

Set `AGENT_BOM_API_KEY` or `AGENT_BOM_API_TOKEN` through your normal secret
manager. Scoped API keys need the `brief:read` grant, which authorizes this
aggregate read of posture, remediation, graph, compliance and scan history.
An existing `posture:read` grant alone does not authorize the brief.
The same JSON is available at `GET /v1/brief?limit=5` and through the
`executive_brief` MCP tool in the `graph`, `audit` and `full` profiles.
MCP reads the persisted control-plane stores and requires the `api` extra.

The brief preserves canonical owner and SLA source fields, ranked graph paths
and their completeness metadata, evaluated-control denominators, and scoped
scan history. Different scans can cover different assets: a historical scan
score is not subtracted from the current tenant-wide score. These are
independent source reads, not one atomic snapshot. The brief is unsigned and
does not attest compliance, execution or exploitation.

For an auditor, follow its `links.evidence_pack` to
`GET /v1/compliance/report/pack` on the same authenticated control plane.
That export requires its own `compliance:read` permission. Save the response
body and signing headers, check the tenant, audit window, expiry and truncation
fields, and verify the signature using the advertised signing configuration.
The pack distinguishes finding counts from control-to-finding mapping rows;
unknown evidence remains unevaluated. A signature alone does not establish
evidence completeness or independent attestation. See
[audit and compliance verification](../deployment/audit-and-compliance-verification.md)
for verification and key-trust boundaries.

## CIS Benchmarks (cloud)

```bash
# AWS CIS Foundations v3.0
agent-bom cloud aws --cis

# Snowflake CIS v1.0
agent-bom agents --snowflake --snowflake-cis-benchmark
```

Requires cloud credentials (AWS_PROFILE or SNOWFLAKE_ACCOUNT/USER/PASSWORD).

## Compliance hub ingest

External scanner evidence can land in the control plane without a native scan
job:

```bash
# CLI — Trivy / Grype / Syft JSON or normalized findings
agent-bom findings push ./scan.json --api-url https://agent-bom.internal.example.com --api-key "$AGENT_BOM_API_KEY"

# API — SARIF, CycloneDX, CSV, or JSON adapters
curl -X POST https://agent-bom.internal.example.com/v1/compliance/ingest ...
```

Ingested rows participate in hub posture (`GET /v1/compliance/hub/posture`) and
the unified findings queue (`GET /v1/findings`). The dashboard `/findings` page
reads the unified list; lifecycle status columns appear only on bulk-ingested
rows. Hub-native listing is available at `GET /v1/compliance/hub/findings` for
API clients — there is no separate hub-findings browser page in the UI today.
