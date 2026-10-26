---
type: llm
---

PASS if the response gives an ordered list grouped by package with the exact current and fixed version for each upgrade (minimist 1.2.5 -> 1.2.6, axios 0.21.0 -> 0.33.0, lodash 4.17.20 -> 4.18.0, express 4.17.1 -> 4.20.0), puts the lodash upgrade first or explicitly first among fixes because its CVE-2021-23337 is known-exploited (KEV), lists event-stream 3.3.6 separately as a malicious package with no fixed version to remove, and proposes the changes without installing anything or editing files.
FAIL if a version is wrong or missing, the known-exploited lodash fix is not ranked first, event-stream is presented as an ordinary upgrade, or the response says it ran an install or changed a file.
