### Fixed

- The reference evidence lab records its public Kubernetes Service as the Kubernetes builder does: a cloud resource exposing the deployment's container, not an MCP server exposing the agent, so the graph no longer labels the internet entry an MCP server and the lab passes the strict relationship contract.
