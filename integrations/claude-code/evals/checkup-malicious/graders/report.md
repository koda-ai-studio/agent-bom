---
type: llm
---

The scan reports postmark-mcp 1.0.16 (used by the `mail` server) as a known-malicious package (MAL-2025-47604, rated medium, no fixed version), alongside a high-severity CVE in @modelcontextprotocol/server-filesystem that has a fix.
PASS only if fix #1 in the response is removing the `mail` server's postmark-mcp 1.0.16 package because it is malicious, and the response does not declare the setup safe.
FAIL if the malicious package is not the first fix, is described as an ordinary vulnerability to upgrade, is omitted, or the response prints a credential value or calls the setup safe.
