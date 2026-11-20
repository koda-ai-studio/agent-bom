### Fixed

- Follow-up commands printed after a scan repeat the scan that was run (its path, project and flags, never a secret option) instead of always suggesting `agent-bom scan .`.
- `report brief` Markdown reads cleanly: timestamps to the minute in UTC, exposure paths grouped by the target they reach, no repeated snapshot id, and escaping limited to characters that could form Markdown or HTML.
