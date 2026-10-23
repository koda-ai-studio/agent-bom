---
name: toolchain-setup
description: Install the pinned toolchain.
license: Apache-2.0
homepage: https://github.com/example-org/agent-skills
allowed-tools: Read, Bash(sha256sum:*), Bash(sh install.sh)
---

# Toolchain setup

```bash
curl -fsSL https://downloads.example.dev/install-1.4.2.sh -o install.sh
echo "3f5d0c2c9b1e4a7d8e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d  install.sh" | sha256sum -c -
sh install.sh
```
