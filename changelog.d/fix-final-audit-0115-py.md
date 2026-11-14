### Changed
- Under `--log-json`, a scan verdict is no longer logged as an error. Each reason a scan exits 1 is one `WARNING` record, `Exiting with code 1: <reason>`, with `context.exit_code` and `context.reason`, instead of two `INFO` lines. Under `-q` the result is one `agent_bom.verdict` record (`WARNING` for FAIL, `INFO` for PASS) whose `context` carries `verdict`, `outcome`, `packages`, `findings`, `counts`, `exit_code`, `reasons` and `report`, instead of three `ERROR` lines. An undelivered `--push-url` report stays `ERROR`.

### Fixed
- `quickstart --run` no longer stops with "Scan exited with status 1" when the graph was persisted and the scan was only partial, most often because the local vulnerability DB is older than 14 days. It warns that coverage is incomplete, prints the DB age with `agent-bom db update`, prints the graph command and URL, honours `--open`, and still exits 1. Any other non-zero scan exit stops onboarding as before. With `--open`, the handoff no longer says to rerun with `--open`.
- Terraform secret detection reads a variable's value only from its `default` attribute, so a `description` is never reported as a hardcoded secret. Names that point at a secret rather than hold one (`*_secret_name`, `*_arn`, `*_ids`, `create_*`, `*_audience`, …) and values that are references or prose (`${…}` interpolations, ARNs, URLs, text with spaces) are skipped. This repository's `deploy/terraform` modules go from 19 findings to none; every hardcoded secret in the IaC test fixtures is still reported.
- TF-SEC-046 no longer flags a Lambda environment variable whose value is a Secrets Manager or SSM ARN, or a reference to one, as a plaintext secret.
- An AI SDK import no longer adds an unpinned `<sdk>@latest` package beside the version the same project's manifest pins (for example `langchain@latest` beside `langchain==0.0.200`), in CLI, API and MCP repository scans. An import with no manifest entry is still reported.

### CI
- The `scan --help` option-count test counts only option rows, so wrapped help text that starts with a flag no longer changes the count; it checks widths 50, 60, 80 and 200.
