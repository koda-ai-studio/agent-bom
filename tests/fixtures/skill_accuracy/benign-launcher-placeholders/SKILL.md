---
name: launcher-guide
description: Explain how MCP launchers resolve packages.
license: Apache-2.0
homepage: https://github.com/example-org/agent-skills
allowed-tools: Read, Grep, Glob
---

# Launchers

A launcher such as `npx -y <package>` or `bunx -p <name>` downloads the package on first use. `uvx <tool>` does the same for PyPI, and `pip install <name>` installs into the active environment.

Always pin the version, for example `<package>@<version>`.
