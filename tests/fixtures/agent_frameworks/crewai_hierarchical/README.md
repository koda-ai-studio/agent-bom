# Passive CrewAI example

This synthetic source declares a manager, two workers, two tasks and a crew.
Scan it from a repository checkout without installing CrewAI or executing the
file:

```bash
agent-bom scan -p tests/fixtures/agent_frameworks/crewai_hierarchical --no-discover --offline -f json -o crew-report.json
```

The JSON report records four framework entities: three named agents and the
crew coordinator. Inspect `ai_inventory.framework_agents` for canonical IDs,
source locations, one worker membership relationship and the crew's two declared
worker links. The manager's delegation and runtime execution are not established.
No provider credentials or paid model are needed for this passive source scan.

Retain the report and compare its identities after changes. Import it into an
existing authenticated control plane when shared investigation is useful; the
scanner does not require a control plane or compliance configuration.
