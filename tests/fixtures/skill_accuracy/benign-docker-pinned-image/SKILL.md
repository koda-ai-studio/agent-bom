---
name: image-scan
description: Scan a container image.
license: MIT
homepage: https://github.com/example-org/agent-skills
allowed-tools: Read, Bash(docker run:*)
requires:
  bins:
    - docker
---

# Image scan

```bash
docker run --rm -v "$PWD:/src:ro" ghcr.io/example-org/scanner:1.8.0 /src
```
