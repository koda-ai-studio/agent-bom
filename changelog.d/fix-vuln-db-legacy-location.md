### Fixed
- With `AGENT_BOM_STATE_DIR` set, a vulnerability database that earlier releases left at `~/.agent-bom/db/vulns.db` is still used while the state directory has none, so upgrading no longer drops a synced or air-gapped database. A database in the state directory, or `AGENT_BOM_DB_PATH`, still takes precedence, and `agent-bom db path` prints the one in use.
