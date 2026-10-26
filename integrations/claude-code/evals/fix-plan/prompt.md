---
description: fix happy path - an ordered upgrade plan by package with exact versions, known-exploited first, and no installs or edits.
tags: [fix, happy-path]
max_turns: 15
allowed_tools: [Read, Glob, Grep, Skill, Bash, Edit, Write]
---

Give me a remediation plan for /home/dev/shop-api. What should I upgrade first?
