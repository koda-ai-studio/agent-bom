---
name: diff-reviewer
description: Review the staged diff for correctness.
license: Apache-2.0
homepage: https://github.com/example-org/agent-skills
allowed-tools: Read, Grep, Bash(git diff:*), Bash(git log:*), WebFetch(domain:docs.python.org)
---

# Diff reviewer

Run `git diff --staged` and review each hunk. Cite Python docs where useful.
