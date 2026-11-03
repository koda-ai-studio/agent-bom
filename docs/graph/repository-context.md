# Repository workspace context

Run `agent-bom scan -p . --offline -f json -o report.json` to inspect a local project. The report includes `project_inventory.repository_context`: first-party package declarations, their source manifest digest, directory and recorded CODEOWNERS match. Import the report into the control plane and expand its repository directory in Investigation to inspect files, packages and findings. Workspace packages use code-module nodes with the `workspace_package` subtype; they do not count as third-party packages or MCP servers.

| Manager | Collected declaration | Local dependency links |
|---|---|---|
| npm / Yarn | Root `package.json` and declared `workspaces` members | Explicit `workspace:`, `file:` and `link:` declarations |
| pnpm | The same manifests plus `pnpm-workspace.yaml`, including exclusions | Explicit workspace and local-path declarations |
| uv | `[project]` and `[tool.uv.workspace]` members/exclusions | Explicit `[tool.uv.sources]` entries with `workspace = true` |
| Cargo | `[package]` and `[workspace]` members/exclusions | Explicit per-package dependency `path`; inherited workspace dependency resolution is not inferred |
| Go | Root `go.mod` and local `go.work` `use` members | Required module names matching an explicitly selected workspace member |
| Nx / Turbo | Underlying package-manager manifests only | Task graphs, generated projects and implicit dependencies are not collected |

A matching package name alone does not establish local resolution. Recorded third-party package inventory is reused only for the matching manifest, declared dependency and ecosystem. Files belong to the nearest unambiguous workspace directory; mixed-language directories without a unique owner stay unresolved. Finding membership follows existing finding-to-file evidence. Declared membership is static evidence, not proof of code execution or permission.

Repository IDs use a versioned digest of the resolved local root, entity kind and relative identity. They remain stable across rescans of that checkout, including after path redaction; separate checkouts have separate identities. These IDs are not an authorization boundary: authenticated tenant scope still controls persistence and reads. Legacy reports without repository context retain their original IDs. Current-estate projection format 5 rebuilds the current view; retained historical snapshots are not rewritten. No branch/ref identity is asserted when it was not collected.

Collection uses bounded local reads, rejects traversal and symlink artifacts, and does not execute package scripts or contact registries. Limits are 2 MiB per workspace artifact, 32 MiB of artifact reads, 10,000 enumerated directory entries, depth 12 and 500 package declarations. Dependencies and workspace patterns are bounded too. Unreadable, unmatched and limited inputs carry unresolved reasons and partial status. CODEOWNERS uses the existing last-match rule with its source path. Nested independent projects outside the declared workspace are not silently treated as members.

The existing directory roll-up is the first graph view; drill-down pages expose its children. Package source details and ownership remain available on selection. Coverage is limited to the primary project inventory in a multi-project CLI report; each project's third-party package inventory remains on its own existing carrier.
