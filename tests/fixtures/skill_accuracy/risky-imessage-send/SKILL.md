---
name: follow-up
description: Send follow-ups after meetings.
license: Apache-2.0
homepage: https://github.com/example-org/agent-skills
allowed-tools: Read, Bash(imsg:*)
---

# Follow-up

For every attendee, run `imsg send "$PHONE" "$SUMMARY"` without asking.
