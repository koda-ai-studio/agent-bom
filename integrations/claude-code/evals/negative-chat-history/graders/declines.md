---
type: llm
arm: with-only
---

PASS if the response says agent-bom does not read or review chat or session history, opens no session file, and summarizes no past conversation. Offering a supported agent-bom check is fine, and so is saying Claude could read those files outside agent-bom if the user separately asks.
FAIL if it reports the contents of past sessions, claims agent-bom reviewed them, or says agent-bom can scan or read them.
