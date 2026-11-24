### Added
- **Am I affected?** `GET /v1/affected?q=` answers for one advisory id (CVE, GHSA, operator advisory) or package (`name` or `name@version`). It returns:
  - a verdict: affected, possibly affected, previously affected (all resolved) or not found, with the basis it rests on
  - every current and past finding across the scans and ingests the findings queue merges, matched exactly on advisory id or package name and version
  - the exposure window: first seen to now, or to when it was resolved
  - known-exploited and fix state, and Internet exposure
  - the affected assets
  - for an advisory, its version ranges matched against stored inventory, so assets no scan has turned into a finding yet still count
  - what the affected hosts reach on the latest graph snapshot (agents, MCP servers, tools, credentials, data stores, cloud resources, identities), from the exploit story

  The same answer is available as `agent-bom findings affected <query>`, the `am_i_affected` MCP tool and `AgentBomClient.affected()`. The Advisories page leads with it and accepts a package as well as an advisory id.
