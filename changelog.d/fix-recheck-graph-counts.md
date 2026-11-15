### Upgrade notes
- A project-local agent (`project`, `project-config`, `ai-inventory`, `python-agents`, `filesystem` and `sast` sources) that is pushed or endpoint-scoped now has a graph id that joins its source scope with its canonical config receipt (`agent:<source>.cfg-<hash>:<name>`). Host-level clients and fleet device agents keep `agent:<source>:<name>`. The former `agent:<source>:<name>` id stays a `previous_graph_ids` alias where it names one agent, so stored references keep resolving.

### Fixed
- Two projects pushed from one host with same-named agents (for example two `ai-inventory` agents) keep their own graph nodes. One project's safety eval no longer evaluates the other project's agent, and coverage-gap findings stay on the agent they belong to.
- `/v1/inventory` lists the same agents as the Agents page and the graph. Projects with only a manifest or only an SDK are inventory, not agents.
- The Agents page counts unique MCP servers, the same count Inventory and the graph show, and gives server configurations as a separate named number. A remote endpoint shared by many agents counts once.
- Findings from a pushed `blast_radius` report that have no graph node id now show reach when an assessed path joins the same advisory and package from an agent the finding lists. Before, every such row showed reach as Unavailable.
- The grouped map always draws the AI-layer groups (Agents, Framework agents, Models, Frameworks, Eval suites), so eval suites no longer fold into "Other groups".
- The grouped map's overview draws links between groups in the same column, so Framework agents show their link to Frameworks.
- The grouped map splits finding groups into "Vulnerabilities · <severity>" and "Policy findings · <severity>" (configuration and policy findings), matching the Findings page lanes. An eval-coverage gap no longer adds to the vulnerability count.
- The Remediation page counts package upgrades, not packages, and large counts on Remediation, Jobs and Findings use thousands separators.
- Display names keep operations acronyms upper-case ("SRE Runbook Agent", "SSO", "SDK", "RBAC", "CI").
- A findings badge on the rightmost node of a left-to-right attack-path graph stays inside the canvas.
- The remediation product capture ends below its content instead of leaving the lower half of the frame empty.
