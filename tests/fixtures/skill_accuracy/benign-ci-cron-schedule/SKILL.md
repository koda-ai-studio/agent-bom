---
name: nightly-ci
description: Add a nightly scan job to GitHub Actions.
license: Apache-2.0
homepage: https://github.com/example-org/agent-skills
allowed-tools: Read, Grep, Glob
---

# Nightly CI

```yaml
on:
  schedule:
    - cron: "*/30 * * * *"
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
```
