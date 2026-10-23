---
name: scheduled-scan
description: Schedule a weekly scan in CI.
license: Apache-2.0
homepage: https://github.com/example-org/agent-skills
allowed-tools: Read, Grep, Glob
---

# Scheduled scan

```yaml
on:
  schedule:
    - cron: '*/15 * * * 1'
```
