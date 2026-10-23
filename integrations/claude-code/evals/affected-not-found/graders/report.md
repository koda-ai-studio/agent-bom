---
type: llm
---

PASS if the response says CVE-2024-3651 was not found in what was scanned, names the scope (for example 1 agent, 3 servers or 2 packages), identifies the advisory as an idna denial-of-service issue of medium severity that is not known-exploited, and notes that the local vulnerability data is stale.
FAIL if it says the user is affected, calls the machine safe or unaffected without limiting the claim to the scanned scope, or omits the stale-data caveat.
