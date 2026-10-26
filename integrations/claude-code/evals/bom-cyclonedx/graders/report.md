---
type: llm
---

The generated BOM is CycloneDX 1.7 with 7 components (2 of type application and 5 libraries: lodash, minimist, event-stream, axios and express) and 34 vulnerabilities affecting all 5 libraries, the worst rated critical (2 critical, 14 high, 17 medium, 1 low).
PASS if the response says it used the generate_sbom tool because no shell was available (or otherwise makes clear the BOM came from that tool), reports the format as CycloneDX, and gives component and vulnerability counts and a worst severity that agree with the numbers above, without claiming a file was written to disk that was not.
FAIL if any count or the worst severity contradicts the BOM, it invents components, or it says it ran a shell command or wrote a file.
