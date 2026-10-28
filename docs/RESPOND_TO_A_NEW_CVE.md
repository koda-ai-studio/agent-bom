# Respond to a new CVE

An operator runbook for "am I affected by CVE-X?": get the advisory in, match
it against what agent-bom has already scanned, read the blast radius, patch,
and prove the fix with a rescan. The worked example is PHP2Shell
(CVE-2026-109618 and CVE-2026-109619), which names the CPE product `php:php`
and is fixed in PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12.

Matching reads stored scan inventory; nothing is rescanned until step 5.

## 0. Refresh the advisory data

```bash
agent-bom db update
agent-bom db status
```

`db update` syncs OSV, Alpine, Debian, EPSS, KEV and NVD by default, so a CVE
that only NVD has analysed so far, with its CPE version ranges, reaches the
local database. Without `NVD_API_KEY` NVD is read keyless (a 14-day window);
with it, 120 days. A keyless run stops after 8 minutes (`--nvd-time-budget`
or `AGENT_BOM_NVD_TIME_BUDGET_SECONDS`) and resumes next run. A capped,
rate-limited or out-of-time NVD run shows `PARTIAL`. Key
handling for workstations, Helm and the GitHub Action is in
[PERMISSIONS.md](PERMISSIONS.md#where-the-keys-live).

## 1. Declare it if no feed has it yet

When the disclosure is public but no feed carries it, declare it as an
operator (emergency) advisory. For PHP2Shell:

```json
{
  "id": "CVE-2026-109618",
  "aliases": ["CVE-2026-109619"],
  "summary": "php2shell: unauthenticated remote code execution in PHP core",
  "severity": "critical",
  "references": ["https://www.php.net/ChangeLog-8.php"],
  "affected": [
    {
      "ecosystem": "generic",
      "name": "php",
      "cpe_product": "php:php",
      "ranges": [
        {"introduced": "8.5.0", "fixed": "8.5.12"},
        {"introduced": "8.4.0", "fixed": "8.4.27"},
        {"introduced": "8.3.0", "fixed": "8.3.36"},
        {"introduced": "8.2.0", "fixed": "8.2.35"}
      ]
    }
  ]
}
```

Declare it in one of three places:

- **Dashboard:** Advisories, Declare tab (`/advisories?tab=declare`).
- **API:** `POST /v1/intel/operator-advisories` with that JSON as the body
  (authenticated, tenant-scoped).
- **CLI:** `agent-bom db advisory add --file php2shell.json`.

When a feed record with the same id or alias later lands on a package, the feed
record wins and the declaration is reported as superseded.

## 2. Match it against stored scans

- **Dashboard:** Advisories, open the advisory (`/advisories?id=CVE-2026-109618`).
- **API:** `GET /v1/intel/advisories/CVE-2026-109618/affected`, with
  `verdict=all|affected|possibly_affected|not_affected`, `limit` (1 to 200,
  default 50) and `cursor` from the previous page's `next_cursor`. It answers
  from the tenant's declaration, else the local feed record (NVD CPE ranges
  included), across the tenant's newest stored scan of each target.
- **MCP:** the read-only `affected_assets` tool (in the `graph` and `full`
  server profiles) takes the same arguments (`advisory_id`, `verdict`,
  `limit`, `cursor`) and returns the same answer.
- **CLI:** `agent-bom db advisory match --id CVE-2026-109618 --format json`
  matches a declared advisory against the most recent saved scan, or the
  reports you pass with `--report` (repeatable). It exits 2 when the result is
  incomplete.

The API and MCP answer has a `summary` (`affected`, `possibly_affected`,
`not_affected`, `clean_scanned`, `assets_examined`, `reports_examined`), a
`coverage` block (`agent_packages`, `standalone_packages` and any
`unexamined_sections`), a `complete` flag and one row per asset and package
with `asset_type` (`mcp_server`, `container_image`, or the recorded type of a
standalone occurrence such as `package`), `asset_node_id`, `installed_version`,
`fixed_version`, `verdict`, `verdict_reason`, `verdict_detail`, `provenance`
and `graph` node ids. Every package occurrence the stored scan recorded is
examined: packages behind MCP servers and scan wrappers, and image or SBOM-only
occurrences the correlation step recorded as their own assets (the same rows
`GET /v1/findings` lists), so `assets_examined` counts images too. The
advisory's `severity` follows the findings policy (a CVSS score first, then the
feed's rating) and says so in `severity_source`. For PHP2Shell across three
stored image scans:

| Asset | Package | Verdict | What to do |
|---|---|---|---|
| official php 8.3.30 runtime | `php` 8.3.30 | affected | patch to 8.3.36 |
| Debian image | `php8.2-cli` 8.2.29-1~deb12u1 | possibly affected (`distro_backport_unverified`) | check Debian's advisory for `php8.2` |
| official php 8.3.36 runtime | `php` 8.3.36 | not affected | none |

Read the answer only for what was scanned: an asset with no stored scan is
not in the answer and is never "not affected". `complete: false` means the
answer is not a clean result (for example, no stored scan, or a version that
could not be ordered).

## 3. Blast radius

Each row's `graph` carries the package, server and agent node ids from the
scan graph. Open them in the security graph (the row's Blast radius link in
the dashboard), call `GET /v1/graph/impact?node=<package_node_id>`, or use the
MCP `exposure_paths` tool with `finding_id` set to the CVE or `node_id` set to
the package node to see which agents, credentials and tools the vulnerable
package reaches. A graph path is likely reachability, not proof of
exploitation.

## 4. Patch

- **Affected:** upgrade to the row's `fixed_version`, the fix on that
  release branch (8.3.30 goes to 8.3.36, not 8.5.12).
- **Possibly affected (distro packages):** distributions backport fixes
  without changing the upstream version, so the upstream range cannot decide
  `php8.2-cli` 8.2.29-1~deb12u1. Follow the distribution's advisory for its
  source package (`php8.2` on Debian) and install the version it names. Once
  the distribution's record is in the local database (`agent-bom db update`),
  it decides the verdict: affected with the distro's fixed version, or clean.

## 5. Verify by rescanning

Rescan the patched asset so a new stored scan replaces the old one, then match
again:

```bash
agent-bom image registry.example.com/shop/web:2.4 --save -f json -o web.json
agent-bom db advisory match --id CVE-2026-109618 --report web.json --format json
```

In the control plane, the asset's next stored scan replaces its older one in the
`GET /v1/intel/advisories/{id}/affected` answer; the row moves to
`not_affected`.

## Counting rule

Possibly-affected (distro) results are listed and visible everywhere (the
affected answer, the scan's `possibly_affected` JSON section, a `note`-level
SARIF result with `properties.verdict: possibly_affected`, CycloneDX
`in_triage`, the job summary of the GitHub Action), but they are **not
counted as confirmed vulnerabilities**: they are left out of severity totals
and vulnerability counts and never fail `--fail-on-severity` or the Action's
`severity-threshold` gate. They stay open until the distribution's record or
your own check decides them.
