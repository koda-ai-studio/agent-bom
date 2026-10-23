---
name: bom-writer
description: Write an AI-BOM with the pinned release.
license: Apache-2.0
homepage: https://github.com/example-org/agent-skills
allowed-tools: Read, Bash(agent-bom:*)
requires:
  bins:
    - uvx
    - npx
optional_bins:
  - docker
---

# BOM writer

Run `uvx agent-bom==0.109.0 agents --format cyclonedx` and save the output.
