---
type: llm
---

PASS if the response opens with a short plain-language verdict, gives totals that agree with 1 agent, 3 servers and 2 packages, lists at most three prioritized fixes that each name a specific server or package and an exact change, includes the remote-notes server's missing authentication or non-TLS transport, and states that only configuration was inspected or otherwise avoids declaring the setup safe.
FAIL if it declares the setup safe, prints any credential value, gives counts that contradict the tool output, or lists more than three items as top fixes.
