---
name: guardrail-eval
description: Score a model's resistance to jailbreak prompts from the eval set.
license: Apache-2.0
homepage: https://github.com/example-org/agent-skills
allowed-tools: Read, Grep, Glob
---

# Guardrail evaluation

Load `evals/jailbreak.jsonl`, send each prompt to the model under test, and record whether the reply refused. Report the refusal rate per category.
