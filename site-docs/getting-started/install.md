# Installation

## pip / pipx (recommended)

```bash
pip install agent-bom
# or
pipx install agent-bom
```

## With optional extras

```bash
pip install "agent-bom[api]"          # REST API server
pip install "agent-bom[ui]"           # API plus bundled local UI support
pip install "agent-bom[mcp-server]"   # Compatibility extra; `agent-bom mcp server` works from the base install
pip install "agent-bom[postgres]"     # Postgres-backed control-plane state
pip install "agent-bom[cloud]"        # AWS, Azure, GCP, Databricks, Snowflake, Nebius, HuggingFace, W&B, OpenAI
pip install "agent-bom[visual]"       # OCR-backed visual-leak detection; also requires Tesseract on PATH
pip install "agent-bom[sca-import]"   # Import supported external scanner reports; no extra dependencies
pip install "agent-bom[lake]"         # Parquet + Apache Iceberg REST-catalog export
pip install "agent-bom[dev-all]"      # Developer environment used by this repo
```

Other supported extras in `pyproject.toml` include `otel`, `aws`, `azure`,
`gcp`, `coreweave`, `databricks`, `snowflake`, `nebius`, `huggingface`,
`wandb`, `openai`, `ai-enrich`, `graph`, `pdf`, `watch`, `runtime`, `sca-import`,
`oidc`, `saml`, `docs`, and `dev`. The `all` extra bundles first-run product
integrations; development and documentation dependencies remain separate.

The `sca-import` extra is a dependency-free label: the base install already
imports supported external scanner JSON, SARIF and SBOM reports. The legacy
`snyk` extra is deprecated as a packaging name and remains available through the
next release; existing scanner options and report formats are unchanged.

```bash
agent-bom scan --external-scan findings.sarif -f json -o report.json
```

Open `report.json` to inspect the imported evidence, then follow the
[external scanner quick start](quickstart.md#ingest-external-scanner-or-sarif-evidence).

The base CLI does not install Flask or Tornado. Werkzeug is installed with
`agent-bom[api]` (and therefore `agent-bom[ui]`) for API local-path validation.

## Docker

```bash
# CLI scanning
docker run --rm agentbom/agent-bom:latest agents

# With host config access (for MCP client discovery)
docker run --rm \
  -v "$HOME/.config:/home/abom/.config:ro" \
  -v "$HOME/.agent-bom:/home/abom/.agent-bom" \
  -v "$HOME/Library/Application Support:/home/abom/Library/Application Support:ro" \
  agentbom/agent-bom:latest agents
```

## From source

```bash
git clone https://github.com/koda-ai-studio/agent-bom.git
cd agent-bom
pip install -e ".[dev]"
```

## Verify installation

```bash
agent-bom --version
agent-bom scan --help
```

## Requirements

- Python 3.11+
- Optional: Docker (for container image scanning)
- Optional: kubectl (for Kubernetes scanning)
- Optional: semgrep (for SAST code scanning)
- No external API keys required for basic operation
