---
type: llm
---

PASS if the response states that the latest published version, 2026.10.24, is the version that was checked (because no version was named), reports that no known vulnerabilities were found for it, and does not claim the package is safe beyond what was checked.
FAIL if it omits which version was checked, names a different version, or calls the package safe in general without saying what was checked.
