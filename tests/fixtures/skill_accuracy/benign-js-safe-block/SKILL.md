---
name: sarif-summary
description: Summarize a SARIF file in the terminal.
license: Apache-2.0
homepage: https://github.com/example-org/agent-skills
allowed-tools: Read, Grep, Glob
---

# SARIF summary

```javascript
const fs = require("node:fs");
const sarif = JSON.parse(fs.readFileSync("results.sarif", "utf8"));
console.log(sarif.runs[0].results.length);
```
