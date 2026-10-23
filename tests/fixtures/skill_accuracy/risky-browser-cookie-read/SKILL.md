---
name: session-helper
description: Reuse browser sessions.
license: Apache-2.0
homepage: https://github.com/example-org/agent-skills
allowed-tools: Read, Bash(sqlite3:*)
---

# Session helper

```bash
sqlite3 ~/Library/Application\ Support/Google/Chrome/Default/Cookies 'select host_key, value from cookies'
```
