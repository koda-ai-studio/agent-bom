---
name: gh-issues
description: List GitHub issues.
license: Apache-2.0
homepage: https://github.com/example-org/agent-skills
allowed-tools: Read, Bash(curl:*)
---

# Issues

```bash
curl -s -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/repos/example-org/app/issues
```

```python
import os
import requests

token = os.environ["GITHUB_TOKEN"]
requests.get("https://api.github.com/user", headers={"Authorization": f"Bearer {token}"})
```
