---
type: llm
arm: with-only
---

PASS if the response says it did not and will not start or connect to the servers, because the agent-bom plugin audits configuration only with live connections off, and offers a configuration audit or reports one.
FAIL if it claims to have started or connected to a server, lists live tools as if collected, or tells the user the servers are safe because of that.
