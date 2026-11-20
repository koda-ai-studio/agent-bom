# Start here by role

agent-bom inventories the AI agents and MCP servers you run, the packages and
models they load, and what each one can reach: credentials, tools, code and
cloud. Every finding sits on one graph, so a vulnerable package is ranked by
what the agent that loads it can touch.

Pick your role. Each path takes about five minutes on a laptop with
[uv installed](https://docs.astral.sh/uv/getting-started/installation/). Scans
run locally and need no account; online scans send package names and versions
to public advisory sources.

| Role | First question answered |
|---|---|
| [AppSec](#appsec) | Which vulnerabilities can an agent actually reach, and what do I fix first? |
| [Platform and DevOps](#platform-and-devops) | How do I gate pull requests and run this for the team? |
| [AI and ML engineer](#ai-and-ml-engineer) | What can my agents, MCP servers and skills reach? |
| [GRC](#grc) | What evidence maps to the AI frameworks I report on? |
| [Leadership](#leadership) | What is our AI supply-chain posture, and what are the top risks? |

## AppSec

**You get** findings ranked by contextual risk: severity, known or likely
exploitation, and reach to agents, credentials and tools. Each comes with a fix
version and a command to verify the fix.

```bash
uvx agent-bom scan .
uvx agent-bom scan . -f sarif -o agent-bom.sarif
uvx agent-bom check requests@2.28.0 --ecosystem pypi
```

**Look at** the **Blast Radius** column (agent → MCP server → credential) and
**PROTECT | Fix First**, where a KEV-listed package is priority P1. A partial
scan is not a clean one: read the coverage warnings before you trust a zero.
`check` gates a single dependency before it is installed.

**Next:** gate pull requests with the [GitHub Action](../integrations/github-action.md)
and see the same chain in the [Blast Radius](../features/blast-radius.md) guide.

## Platform and DevOps

**You get** a pull-request gate with SARIF and a findings comment, the same
gate on your laptop, and a local control plane that retains scans and serves
the graph.

```yaml
- uses: actions/checkout@v4
- uses: koda-ai-studio/agent-bom@v0
```

```bash
uvx agent-bom scan . --fail-on-severity high --fail-on-kev
uvx --from 'agent-bom[ui]' agent-bom up
```

**Look at** the exit code: `0` passes, `1` is a security verdict or an
incomplete assessment ([exit codes](../reference/exit-codes.md)). `up` serves
the API and dashboard on `http://127.0.0.1:8422`; open **Connections** to add a
read-only cloud source or **New Scan** to scan a repository.

**Next:** [choose a deployment](../deployment/overview.md): the one-machine
[Docker pilot](../deployment/docker.md), then the
[authenticated self-hosted instance](../deployment/authenticated-hosted-instance.md)
or the [Helm chart](../deployment/control-plane-helm.md).

## AI and ML engineer

**You get** every agent and MCP server configured in the project and on this
machine, the packages behind them, the credential names they are given (never
the values).

```bash
uvx agent-bom scan --demo --offline
uvx agent-bom scan -p .
uvx agent-bom skills scan .
```

**Look at** **DISCOVER | Agents** (servers, packages and credentials per
agent) and the **AI agent can reach a credential or privileged tool**
findings. The demo uses labelled sample data and exits `1` on purpose: the
sample trips the security gate. `skills scan` reads instruction and skill
files such as `CLAUDE.md` and `.cursor/rules` for risky behavior, for example a
remote script piped to a shell; it exits `2` when the project has none.

**Next:** use agent-bom as a tool inside your coding agent with the
[MCP server](mcp-server.md), and see which AI platforms and GPU clouds are
covered in the
[AI infrastructure coverage matrix](../architecture/ai-infrastructure.md#coverage-matrix).

## GRC

**You get** a machine-readable report, an auditor-facing narrative per
framework (OWASP LLM, OWASP MCP, OWASP Agentic, MITRE ATLAS, EU AI Act, NIST AI
RMF and more) and an AI-BOM in CycloneDX.

```bash
uvx agent-bom scan . -f json -o agent-bom-report.json
uvx agent-bom report compliance-narrative agent-bom-report.json --framework eu-ai-act -o eu-ai-act-narrative.md
uvx agent-bom scan . -f cyclonedx -o ai-bom.cdx.json
```

**Look at** the controls marked **not evaluated** as well as the failures: an
unevaluated control is missing evidence, not a pass. Mappings are review
evidence, not audit certification.

**Next:** the [compliance mappings](../features/compliance.md), and the signed
compliance pack from a control plane described in the
[executive brief](../deployment/executive-brief.md#verify-the-separate-signed-pack).

## Leadership

**You get** one page: a posture grade, the top remediation priorities with
owner and SLA, the ranked exposure paths and technical control evidence.

```bash
uvx --from 'agent-bom[ui]' agent-bom quickstart --run --open
```

This scans a bundled sample AI stack, starts the local dashboard and opens its
security graph. From **Overview**, open **Executive brief**. To export the
brief as Markdown from your own control plane, start the server with a key you
choose, then request the brief from a second terminal with the same key:

```bash
export AGENT_BOM_API_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
uvx --from 'agent-bom[ui]' agent-bom serve --persist ~/.agent-bom/control-plane.db
uvx agent-bom report brief --api-url http://127.0.0.1:8422 > executive-brief.md
```

**Look at** the grade and the open issue groups, then the ranked exposure
paths: each one starts at an agent and ends at what it can reach. Counts are
correlated issue groups, not raw finding occurrences.

**Next:** have the team run the [authenticated self-hosted instance](../deployment/authenticated-hosted-instance.md)
so the brief covers your real estate, then read the
[executive brief guide](../deployment/executive-brief.md).
