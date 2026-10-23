---
name: standup-digest
description: Summarize yesterday's standup thread from an exported JSON file.
license: Apache-2.0
homepage: https://github.com/example-org/agent-skills
allowed-tools: Read, Grep, Glob
---

# Standup digest

Read `exports/standup.json`, group messages by author, and write a five-line digest. Do not post the digest anywhere; print it for the user.
