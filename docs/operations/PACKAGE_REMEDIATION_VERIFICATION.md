# Verify an installed Python package update

Use `agent-bom verify-remediation` to answer one bounded question: did the
installed distribution metadata in this directory move from an affected version
to a fixed version for this exact advisory?

The command reads files only. It imports no inspected package, installs nothing,
makes no network requests, and closes no campaign. The output retains the
before/after receipt digests, versions, advisory digest, scope and reason codes.
It does not establish the version loaded by an already-running process.

## Capture the baseline

From a source checkout, install the command with `uv sync`, then use `uv run
agent-bom` below. Use a **separate** evidence directory outside the installation.
Identify the actual `site-packages` directory used by the affected application;
do not substitute its requirements file or the scanner's own environment.

```bash
CASE=$(mktemp -d /tmp/agent-bom-remediation.XXXXXX)
SITE_PACKAGES=/absolute/path/to/application/.venv/lib/python3.13/site-packages

# Example advisory for urllib3; select the advisory affecting your installation.
curl --fail --show-error --location \
  https://api.osv.dev/v1/vulns/GHSA-q2q7-5pp4-w6pg > "$CASE/advisory.json"

uv run agent-bom verify-remediation capture \
  --site-packages "$SITE_PACKAGES" --package urllib3 \
  --tenant-id local-review --advisory "$CASE/advisory.json" \
  --output "$CASE/before.json"
```

This example advisory's [upstream record](https://github.com/advisories/GHSA-q2q7-5pp4-w6pg)
identifies a specific affected-version range and fix. A fix for one advisory is
not a recommendation to install that historical version today. Retain the
original downloaded JSON and use the **same bytes/content** for both captures.
An updated advisory requires a new reviewed comparison; it cannot silently
change the baseline. Obtaining current advisory data is the operator's step,
not something the offline comparison does automatically.

A complete capture exits `0`. An unavailable capture exits `2` and still writes
its reasons, such as missing/duplicate package metadata or unsupported layouts.
Input, permission and existing-output errors exit `1`. Every output must be new.

## Apply the approved update and capture again

Apply the update through the application's normal, separately authorized change
process. Retain its change receipt. Restart or redeploy where required, and
perform the application's own runtime checks. Then run:

```bash
uv run agent-bom verify-remediation capture \
  --site-packages "$SITE_PACKAGES" --package urllib3 \
  --tenant-id local-review --advisory "$CASE/advisory.json" \
  --output "$CASE/after.json"

uv run agent-bom verify-remediation compare \
  --before "$CASE/before.json" --after "$CASE/after.json" \
  --output "$CASE/verification.json"
```

| Outcome | Exit | Meaning and next action |
| --- | --- | --- |
| `verified_for_selected_advisory` | `0` | The baseline was affected, the package remains installed, and its higher version crosses a fix in the baseline's affected range. Confirm running-process/deployment state independently. |
| `still_affected` | `1` | The candidate version still matches this advisory. Check the selected installation and update, then retain another capture. |
| `unavailable_evidence` | `2` | A required comparison condition is missing. Read `reason_codes`; restore evidence and recapture instead of declaring success. |

Comparison checks exact directory identity, tenant label, package, advisory
content, distinct receipts, ordered timestamps and candidate freshness (one hour
by default, configurable with `--max-age-seconds` up to one day). Deleting a
package, changing directories, rebuilding the directory under a new filesystem
identity, unsupported/Git-only ranges, an advisory withdrawal, or a range limit
without a fix cannot prove this update. A baseline that was already unaffected
cannot become a remediation success.

**Example prompt for a shell-capable assistant:**

> Compare the retained before/after package captures using `agent-bom
> verify-remediation compare`. Report its outcome, versions, advisory ID,
> evidence digests and reason codes. Explain what remains unverified before
> recommending whether to close the change. Do not edit either capture or apply
> an update.

The existing MCP `graph_diff` tool remains a graph comparison. It does not run
this command or authenticate local receipts. Keep graph snapshot and affected
agent IDs alongside the package receipts when investigating impact; package
metadata alone does not establish an agent-to-installation relationship.

## Evidence and trust boundaries

The receipt includes the original selected `METADATA` text and its digest.
Keep it private: installed metadata may contain local paths or package-origin
URLs. Digests detect edits relative to a retained receipt; an actor who can
rewrite the file can also recompute its digest. Host/directory identity and the
tenant label are local correlation fields, not authenticated identity or access
grants. `independently_verified` and `runtime_loaded_version_verified` stay false.

The collector supports ordinary `.dist-info/METADATA` records in one explicit
directory. It rejects missing, malformed, duplicate and symlinked metadata and
legacy `.egg-info` layouts. It does not inspect other import paths, editable
source trees, vendored copies, containers on another host or package-file
integrity. Inventory collection is bounded; exhaustion produces unavailable
evidence. The version evaluator accepts explicit PyPI ecosystem ranges and uses
the scanner's shared OSV window semantics. Unsupported conditions stay unknown.

No usage telemetry is added. For relationship-level checks use
[Measure an investigation and rescan](INVESTIGATION_MEASUREMENT.md); provider
access changes need the separate [recorded access receipt contract](../graph/remediation-receipts.md).
