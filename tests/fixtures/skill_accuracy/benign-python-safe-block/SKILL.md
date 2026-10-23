---
name: report-parser
description: Summarize a scan report JSON.
license: Apache-2.0
homepage: https://github.com/example-org/agent-skills
allowed-tools: Read, Grep, Glob
---

# Report parser

```python
import json
from pathlib import Path

report = json.loads(Path("report.json").read_text())
print(len(report["findings"]))
```
