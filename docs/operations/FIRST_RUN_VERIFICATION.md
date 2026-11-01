# Verify the published first run

This check installs no source code into the selected environment. It exercises
the published package's offline demo, persisted sample graph, loopback server,
and rendered graph in desktop/mobile light and dark themes.

From a source checkout, create a clean environment outside the repository:

```bash
python3 -m venv /tmp/agent-bom-first-run-venv
/tmp/agent-bom-first-run-venv/bin/python -m pip install 'agent-bom[ui]==0.112.1' 'playwright==1.63.0'
/tmp/agent-bom-first-run-venv/bin/python -m playwright install chromium
/tmp/agent-bom-first-run-venv/bin/python scripts/verify_first_run.py \
  --expected-version 0.112.1 --output /tmp/agent-bom-first-run-evidence
```

Choose new directories for each qualification. The runner refuses to overwrite
evidence and rejects editable installations. Use the explicit release version
being evaluated; do not infer it from the source version on main.

The `receipt.json` records the installed version, platform, expected and actual
exit codes, timings, exact graph snapshot and node/edge counts. A partial report,
wrong snapshot, empty graph, missing relationship endpoint, failed page load,
browser exception, incorrect theme, or horizontal page overflow fails the run.
The disposable server is stopped even on failure. Logs and failed receipts stay
in the output directory. Browser captures demonstrate rendering; a person must
still assess readability and whether the result is useful.

The demo expects exit `1` for its intentional vulnerability. Offline quickstart
skips package-CVE lookup and verifies inventory relationships only. A rendered
graph is not a clean security verdict or evidence of successful exploitation.
The loopback-only server explicitly allows anonymous local evaluation; this
does not qualify shared-instance authentication or production deployment.

The **Published first-run journey** workflow runs on Linux and macOS. It selects
a published release independently of the checked-out source, measures uncached
package installation separately, and retains screenshots and receipts on
failure. Browser-driver installation is outside the package-install timer.
Manual runs can select an exact published version. Automated sample timings do
not measure human comprehension, a clean machine's prerequisite setup, or
external-user adoption. Five minutes is a target until repeated measurements
support a scoped claim.

Next, follow the [first-run guide](../FIRST_RUN.md) on a repository you own and
review findings and coverage. For a controlled before/after change, use the
[connected component example](../../examples/connected-bom/README.md).
