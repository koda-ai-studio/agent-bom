# agent-bom lookup

Two read-only lookups from [agent-bom](https://github.com/koda-ai-studio/agent-bom), on a
public MCP server with no account or sign-in.

| Tool | Input | Returns |
|---|---|---|
| `check` | One package name, ecosystem and optional version | Known vulnerabilities, malicious-package advisories and fixed versions |
| `intel_lookup` | One CVE, GHSA or OSV id | Summary, severity, CVSS, affected ranges, fixed versions, EPSS and CISA KEV status |

Both tools are annotated read-only, non-destructive and open-world (they describe public
packages and advisories). The server registers no other tool, prompt or resource.

## What is sent, and where

- The assistant sends the server only the tool arguments above.
- `check` sends the package name, ecosystem and version to `api.osv.dev` and
  `api.github.com` (public security advisories), and for npm and PyPI to
  `registry.npmjs.org` or `pypi.org` to resolve a latest version and confirm the version
  exists.
- `intel_lookup` reads the server's own advisory database and sends nothing onward.
- The server never asks for files, source code, credentials or chat history.

The server keeps a bounded in-memory record of recent calls (tool name, a per-address rate
bucket, status and timing, not the arguments) and an on-disk cache of OSV answers keyed by
package, both lost when the server is replaced. The hosting platform keeps its own request
logs. See the [privacy notice](https://koda-ai-studio.github.io/agent-bom/privacy/) and
[docs/PERMISSIONS.md](https://github.com/koda-ai-studio/agent-bom/blob/main/docs/PERMISSIONS.md#public-lookup-server).

## Limits

- Lookups only. It cannot scan your computer, repositories, MCP configuration or cloud
  accounts; run the agent-bom CLI on your own machine for that.
- OS packages (`deb`, `apk`, `rpm`) are refused, because they would describe the server's
  operating system, not yours.
- The advisory database covers OSV for PyPI and npm, CISA KEV and FIRST EPSS, loaded when
  the server starts. A miss reports what was searched instead of claiming the advisory
  does not exist.
- Rate limits are per client address and in total, shared by every anonymous user.

## Support

[Issues](https://github.com/koda-ai-studio/agent-bom/issues) for questions, and the
[security policy](https://github.com/koda-ai-studio/agent-bom/security/policy) for
vulnerability reports.
