---
description: scan a project - leads with fixable critical and high findings, lists the malicious package, and never calls reachability confirmed or the project safe.
tags: [scan, happy-path]
max_turns: 15
allowed_tools: [Read, Glob, Grep, Skill]
---

Scan the project in /home/dev/shop-api for vulnerable or malicious dependencies.
