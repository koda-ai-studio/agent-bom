# MITRE ATLAS associations and source receipts

Run a scan and retain the JSON artifact:

```bash
agent-bom scan --demo --offline -f json -o atlas-example.json
```

The demo uses synthetic findings and may exit nonzero for its seeded
vulnerabilities. Inspect `findings[].atlas_tags` and
`findings[].evidence.atlas_mapping_evidence`; an empty mapping is a valid result.
For your own inventory, run `agent-bom scan -f json -o scan.json`, then review each
association's source chain before using it in an investigation.

## What a package mapping means

A package finding must have AI/MCP inventory context and an advisory CWE with
an explicit relationship in the locally selected catalogs:

`advisory CWE → CAPEC/ATT&CK bridge → ATT&CK technique → ATLAS ATT&CK reference`

The scanner matches the exact ATT&CK ID. It does not promote a sub-technique to
its parent or infer jailbreak, poisoning, exfiltration, compromise or business
impact from severity, an AI-looking package name, a declared tool or a credential
reference. Without a supported chain and source digests, it abstains.

For example, the bundled catalog associates CWE-285 with ATT&CK T1005, and
ATLAS AML.T0037 explicitly references T1005. This is a weakness association in
AI/MCP inventory. It is not evidence that anyone collected local data.

The source catalogs are maintained by [MITRE ATT&CK](https://attack.mitre.org/)
and [MITRE ATLAS](https://github.com/mitre-atlas/atlas-data). The bundled snapshot
is versioned reference material; catalog membership and vocabulary size are not
detection coverage. Other finding types retain their own technique evidence.

## Frozen source receipts

New package mappings retain `basis: catalog_weakness_association`, CWE IDs,
`attack_reference`, the ATLAS version, both normalized catalog SHA-256 digests,
and `execution_proven: false`. Receipts are frozen when the scan assigns tags;
viewing an older finding does not recompute its mapping with a newer catalog.
Legacy tags without receipts remain readable but acquire no retroactive source
claim. Conflicting catalog receipts remain separate during graph aggregation.

- JSON, SARIF and scan API responses carry the same mapping receipt.
- CycloneDX properties and SPDX annotations retain package-scoped receipts.
- HTML and Markdown reports show the source chain and hashes.
- Scan-result cards expose **Mapping sources**; graph receipts accompany the
  finding relationship and never create a traversal edge.
- MITRE ATT&CK and ATLAS are applicability overlays, excluded from control pass
  rates in the API, dashboard and HTML report.

Neither the presence nor absence of a tag establishes observed execution,
effective access, exploitability, certification or an audit opinion.

## Inspecting and refreshing catalogs

```bash
agent-bom db framework-status --framework atlas --stale-after-days 180
agent-bom db update-frameworks --framework atlas
agent-bom db framework-status --framework atlas --stale-after-days 180 --fail-on-stale --format json
```

The update command refreshes the local catalog cache; it does not rewrite a
past scan's receipts or the package's bundled snapshot. Review catalog status
and pinned source metadata independently of finding applicability.

## Supported label vocabulary

The following 65 labels are available for findings. This is a vocabulary, not
a claim that static scanning detects all these techniques. The package mapper
emits only entries with a supported source chain. The bundled catalog contains
additional reference entries; `tests/test_atlas_fetch.py` checks that every
supported label exists in that snapshot.

| Technique | Name |
|---|---|
| `AML.T0000` | Search Open Technical Databases |
| `AML.T0001` | Search Open AI Vulnerability Analysis |
| `AML.T0002` | Acquire Public AI Artifacts |
| `AML.T0004` | Search Application Repositories |
| `AML.T0005` | Create Proxy AI Model |
| `AML.T0006` | Active Scanning |
| `AML.T0007` | Discover AI Artifacts |
| `AML.T0008` | Acquire Infrastructure |
| `AML.T0010` | AI Supply Chain Compromise |
| `AML.T0010.001` | AI Software |
| `AML.T0010.002` | Data |
| `AML.T0010.003` | Model |
| `AML.T0010.004` | Container Registry |
| `AML.T0011` | User Execution |
| `AML.T0011.001` | Malicious Package |
| `AML.T0012` | Valid Accounts |
| `AML.T0013` | Discover AI Model Ontology |
| `AML.T0014` | Discover AI Model Family |
| `AML.T0015` | Evade AI Model |
| `AML.T0016` | Obtain Capabilities |
| `AML.T0017` | Develop Capabilities |
| `AML.T0018` | Manipulate AI Model |
| `AML.T0018.000` | Poison AI Model |
| `AML.T0018.001` | Modify AI Model Architecture |
| `AML.T0018.002` | Embed Malware |
| `AML.T0019` | Publish Poisoned Datasets |
| `AML.T0020` | Poison Training Data |
| `AML.T0024` | Exfiltration via AI Inference API |
| `AML.T0024.001` | Invert AI Model |
| `AML.T0024.002` | Extract AI Model |
| `AML.T0025` | Exfiltration via Cyber Means |
| `AML.T0029` | Denial of AI Service |
| `AML.T0031` | Erode AI Model Integrity |
| `AML.T0034` | Cost Harvesting |
| `AML.T0035` | AI Artifact Collection |
| `AML.T0036` | Data from Information Repositories |
| `AML.T0037` | Data from Local System |
| `AML.T0040` | AI Model Inference API Access |
| `AML.T0043` | Craft Adversarial Data |
| `AML.T0043.004` | Insert Backdoor Trigger |
| `AML.T0046` | Spamming AI System with Chaff Data |
| `AML.T0048` | External Harms |
| `AML.T0049` | Exploit Public-Facing Application |
| `AML.T0050` | Command and Scripting Interpreter |
| `AML.T0051` | LLM Prompt Injection |
| `AML.T0051.000` | Direct Prompt Injection |
| `AML.T0051.001` | Indirect Prompt Injection |
| `AML.T0052` | Phishing |
| `AML.T0052.000` | Spearphishing via Social Engineering LLM |
| `AML.T0053` | AI Agent Tool Invocation |
| `AML.T0054` | LLM Jailbreak |
| `AML.T0055` | Unsecured Credentials |
| `AML.T0056` | Extract LLM System Prompt |
| `AML.T0057` | LLM Data Leakage |
| `AML.T0063` | Discover AI Model Outputs |
| `AML.T0064` | Gather RAG-Indexed Targets |
| `AML.T0065` | LLM Prompt Crafting |
| `AML.T0066` | Retrieval Content Crafting |
| `AML.T0067` | LLM Trusted Output Components Manipulation |
| `AML.T0068` | LLM Prompt Obfuscation |
| `AML.T0069` | Discover LLM System Information |
| `AML.T0070` | RAG Poisoning |
| `AML.T0071` | False RAG Entry Injection |
| `AML.T0073` | Impersonation |
| `AML.T0074` | Masquerading |
