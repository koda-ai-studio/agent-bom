# Submitting the agent-bom plugins

The plugins pin agent-bom 0.114.0. Started from their lock files, the default and audit
servers offer 8 and 10 tools, and neither offers `agent_activity`, the chat-history tool
that the Claude directory policy forbids.

```bash
make plugin-submission-check
```

This fails while any pin is below the release floor, either legal page is a draft, or
review cases are missing. It is not part of `make preflight`.

Rules change. Reread the linked pages before submitting; they were last checked on
2026-11-05.

## What is ready, with evidence

| Requirement | Status | Evidence |
|---|---|---|
| Name, version, description, author, license, icon | Ready | `claude plugin validate --strict --profile directory` passes on both Claude plugins; `scripts/build_codex_plugin_zip.py` checks the OpenAI limits |
| Skill frontmatter and least-privilege tool lists | Ready | `tests/test_claude_code_plugin.py` |
| Tool annotations match the code | Ready | `tests/test_plugin_directory_readiness.py`, [table](PERMISSIONS.md#plugin-hook-and-tool-hints) |
| No chat history access | Ready | Discovery test with planted session files; `tools/list` on both pinned servers |
| Network destinations disclosed | Ready | `tests/test_plugin_egress_hosts.py`, [PERMISSIONS](PERMISSIONS.md) |
| Hook disclosure | Ready | Guard [README](../integrations/agent-bom-guard/README.md) and [privacy page](../site-docs/privacy.md) |
| Repository limits (Claude) | Ready, close to one limit | 9,120 files and folders against a limit of 10,000; 34 MiB archive against 50 MiB (2026-11-10). Recheck before each submission |
| Review cases | Written and run | [PLUGIN_REVIEW_CASES.md](PLUGIN_REVIEW_CASES.md) |

Evals on 2026-11-05 (branch code with recorded tool output, one run of each of 18 cases, no
baseline, about $3.69 list price): 17 cases scored 1.0. `bom-cyclonedx` scored 0.8 on its
judged report grader, and failed that grader in 1 of 3 more runs (it also passed in an earlier run);
the answers read as correct but framed counts differently from the rubric. The full run of
three with a baseline has not been done.

## Steps for both directories

1. For a new release, `scripts/bump-version.py` moves the versions, skill pins and
   `uv.lock`. Submit from the release tag.
2. Check that `site-docs/privacy.md` and `site-docs/terms.md` still match what the plugins
   do. They cover local and self-hosted use. A public hosted service needs a named operator,
   contact, law and retention added first.
3. Run `python scripts/build_claude_directory.py` to refresh the Claude-only
   directory distribution, then `make plugin-submission-check`. The generated
   bundle retains the source launcher, lockfile and nine skills, without the
   local Codex manifest or evaluation fixtures. Edit `integrations/claude-code`
   and regenerate; do not hand-edit the bundle.
4. Rerun the [review cases](PLUGIN_REVIEW_CASES.md) and the evals against the release:

   ```bash
   cd integrations/claude-code
   claude plugin eval . --trust-plugin --max-cost-usd 60
   ```

   Three runs of each of the 18 cases, with and without the plugin, is about 108 agent runs on your
   plan or API bill. The result is written under `evals/results/`, and the report is
   published to your claude.ai account unless you add `--no-publish`.

## Claude directory (first)

Source: [submit](https://claude.com/docs/plugins/submit),
[checklist](https://claude.com/docs/plugins/pre-submission-checklist),
[policy](https://support.claude.com/en/articles/13145358-anthropic-software-directory-policy).

Submit each plugin separately at [claude.ai/directory/manage](https://claude.ai/directory/manage),
from a paid account on the organization that should own the listing, with GitHub connected.

1. **Submit new**, then **Plugin bundle**. Repository `koda-ai-studio/agent-bom`, plugin
   path `integrations/claude-directory`, tracked branch or tag: the tested release source.
   The directory BOM skill uses only `generate_sbom`; it returns a document in the
   conversation and has no cloud/image BOM or shell fallback. Repository and Codex
   editions retain their separate CLI workflows.
2. Select **Validate**. Fix anything marked **Blocks**, then **Re-validate**.
3. Review the reported holds separately from blockers. The readable Python launcher
   may be held for a reviewer; a hold is not a rejection or a validation pass.
   The guard is a separate submission, with reviewer notes in its own README.
4. Data handling answers, as the code behaves: reads local configuration and any files
   named; sends package names and versions to the public services in
   [PERMISSIONS](PERMISSIONS.md); keeps a local cache only; not aimed at people under 18.
5. Check the contact address, select the acknowledgements, then **Submit for review**.
6. Repeat with plugin path `integrations/agent-bom-guard`.
7. Paste three prompts from [the review cases](PLUGIN_REVIEW_CASES.md) if asked. Neither
   plugin has an account or a remote service; say so where the policy asks for a test account.

Test on each surface first. Skills load in claude.ai chat but local MCP servers do not, so
there the skills only say they need Claude Code. Hooks and local servers load in Cowork when
the session runs on your computer; this was not tested here. See
[platform support](https://claude.com/docs/plugins/platform-support).

## OpenAI directory (second)

Source: [submit](https://developers.openai.com/plugins/deploy/submission),
[guidelines](https://developers.openai.com/plugins/plugin-guidelines),
[desktop-only](https://developers.openai.com/plugins/deploy/desktop-only),
[errors](https://developers.openai.com/plugins/deploy/submission-errors).

**Choose the route before the first upload.** A skills-only plugin cannot have an MCP
server added later; an MCP version would be a new plugin. OpenAI no longer accepts
skills-only plugins, so Route B is the path forward and Route A stays a draft.

### Route A: skills-only, desktop-only (ready)

The package in `integrations/codex`, built by `python scripts/build_codex_plugin_zip.py`. It
runs the pinned CLI from the shell, so it sets `requires_local_executor` and gets a
**Desktop only** badge. It has no hooks and no MCP server.

1. Complete individual or business verification in OpenAI Platform settings, for the name
   the listing will show.
2. Because the plugin's core value needs local execution and access to local files, OpenAI
   asks you to contact your OpenAI partner first. If the portal says
   `requires_local_executor` is not allowed, send your organization ID to your OpenAI
   representative.
3. Open [Plugins](https://platform.openai.com/plugins), select **Upload new or existing
   plugin**, choose your identity, and upload the ZIP.
4. Wait for the skill scans, which can take up to two hours. Fix any findings by uploading a
   corrected ZIP.
5. Submit, complete the attestations, and publish after approval.

OpenAI asks for the 5 positive and 3 negative cases and the video on MCP submissions. Keep
them ready in case the review asks.

### Route B: remote MCP, the public lookup edition (code ready, not deployed)

OpenAI no longer accepts skills-only plugins, so Route B is a **new** plugin,
`agent-bom-lookup`, with its own package in `integrations/openai-mcp`, built by
`python scripts/build_openai_mcp_plugin_zip.py`. The Route A package and its draft stay as
they are. The listing connects to one public, no-login MCP server that registers only
`check` and `intel_lookup`, run from `deploy/docker/Dockerfile.public-mcp` on its own
hostname. It has no account, OAuth, reviewer login or test credentials.

The OAuth server at `https://agent-bom-mcp.up.railway.app/mcp` is a different service and
is unchanged: on 2026-11-12 its `/health` reported 0.114.0, the `scan` profile, OAuth
required and 7 read-only tools. It is not part of this listing, and the builder refuses
its URL.

Sources, read on 2026-11-12:
[submission](https://developers.openai.com/plugins/deploy/submission),
[guidelines](https://developers.openai.com/plugins/plugin-guidelines),
[errors](https://developers.openai.com/plugins/deploy/submission-errors), and the
[apps submission page](https://developers.openai.com/apps-sdk/deploy/submission) for domain
verification.

| Requirement (source) | Where it is met |
|---|---|
| ZIP with root `plugin.json` (Agent Plugins format, settings under `extensions.com.openai`) and `mcp.json`; MCP config in the first upload (submission) | `integrations/openai-mcp/`; the builder allowlists 5 files |
| Exactly one remote server, `streamable-http`, HTTPS URL; no `headers`, `clientSecret` or other credentials; not `type: "none"` (submission) | `mcp.json`; the builder refuses anything else, a query or fragment, a path other than `/mcp`, and the OAuth host |
| No `apps`, `.app.json`, hooks, `test_credentials` or `reviewer_instructions` (submission) | Builder refuses them, plus `skills` and `requires_local_executor` |
| `name` ≤64 lowercase/digits/single hyphens, semantic `version`, `description` ≤1,024, `author.name` ≤120, HTTPS `homepage` (submission, errors) | Builder |
| `displayName` and `shortDescription` ≤30, `longDescription` ≤4,000, `developerName` ≤80, `category`, `capabilities` ≤20 × 120, up to 3 `defaultPrompt` ≤128 without @mentions, unique (final-submission limits) | Builder |
| Website, support, privacy and terms URLs, all HTTPS ≤1,024, no credentials (required for MCP review) | `plugin.json`; builder. **The privacy notice does not yet cover a hosted service: owner step 9** |
| `logo` and `composerIcon`, `./` paths, square PNG 48-4,096 px, ≤5 MiB; brand color ≥2:1 against white (errors) | `assets/icon.png` (1,024 px); builder computes the contrast |
| Stable public HTTPS endpoint; no authentication is supported (submission) | `Dockerfile.public-mcp` on its own hostname: `--public-readonly --profile public`; card reports no scheme |
| Explicit boolean `readOnlyHint`, `destructiveHint`, `openWorldHint` on every tool, each with a justification (guidelines; `annotations_required`, `justification_required`) | All three set on both tools (`tests/test_mcp_public_edition.py`); justifications below for the portal |
| Descriptions match behavior and schema (guidelines) | `check` states that `deb`/`apk`/`rpm` are refused on a public server; `intel_lookup` states its source and what a miss means |
| Minimal inputs; no chat history, location, credentials or files (guidelines) | Arguments are a package coordinate or one advisory id, strings ≤256 characters, bodies ≤16 KiB |
| Domain verification: exact token as plain text at `/.well-known/openai-apps-challenge` on the MCP host (submission; `domain_verification_required`) | `src/agent_bom/mcp_tools/openai_challenge.py`, from `AGENT_BOM_OPENAI_APPS_CHALLENGE`; 404 when unset |
| Exactly 5 positive cases (`description`, `prompt`, `tools_triggered`, `expected_behavior`) and 3 negative (`description`, `prompt`) under `review.test_cases` (submission) | `plugin.json`; the builder enforces the counts and that each triggered tool is served. Facts checked against the built image on 2026-11-12 |
| `publication.release_notes` (errors) | `plugin.json` |
| Demo recording, a current tool scan of the production server, verified developer (submission, guidelines) | Owner steps 8, 10 and 12 |

Tool annotation justifications to paste in the portal:

- `check`: read-only, because it looks up advisories for one package coordinate and changes
  nothing for the user (its only write is the server's own lookup cache); not destructive,
  because it deletes, overwrites and sends nothing on the user's behalf; open-world,
  because it queries public advisory services and registries about any public package.
- `intel_lookup`: read-only, because it reads one record from the server's advisory
  database; not destructive, for the same reason; open-world, because CVE, GHSA and OSV
  advisories are public, open-ended records.

Known review risks: `check` answers include data-freshness timestamps and a deterministic
package identifier, which the guidelines ask to omit unless needed; anonymous users share
rate limits, so a busy period returns rate-limit errors; GitHub's unauthenticated
advisory API allows 60 requests an hour per address, so without `GITHUB_TOKEN` the
GitHub part of `check` degrades to partial coverage, which `check` reports.

#### Owner checklist

1. Merge the branch and cut the release that contains it; deploy that tag.
2. In Railway, in the project that holds the OAuth service, add a **new** service from
   the `koda-ai-studio/agent-bom` repository, named `agent-bom-lookup`. New Railway
   services cannot use config as code, so the root `railway.json` does not apply to it.
   Do not change the OAuth service.
3. On the new service set these variables:

   | Variable | Value |
   |---|---|
   | `RAILWAY_DOCKERFILE_PATH` | `deploy/docker/Dockerfile.public-mcp` |
   | `AGENT_BOM_MCP_PUBLIC_URL` | `https://<hostname from step 4>` |
   | `AGENT_BOM_MCP_PUBLIC_TRUSTED_PROXY_HOPS` | `1` (verify in step 6) |
   | `AGENT_BOM_MCP_PUBLIC_CALLER_RATE_LIMIT` | `30` (default; per address per minute) |
   | `AGENT_BOM_MCP_PUBLIC_TOTAL_RATE_LIMIT` | `300` (default; all anonymous callers per minute) |
   | `RAILWAY_HEALTHCHECK_TIMEOUT_SEC` | `300` |
   | `GITHUB_TOKEN` | Optional: a fine-grained token with no repository access, only to raise the GitHub advisory rate limit |

   Do not set `AGENT_BOM_MCP_BEARER_TOKEN`, any `AGENT_BOM_MCP_OAUTH_*` variable or
   `AGENT_BOM_MCP_PUBLIC_READONLY` (the image fixes the flags; OAuth makes startup fail).
   Keep one replica: rate windows are per process.
4. **Settings:** healthcheck path `/health`. **Networking:** generate a domain, ideally
   `agent-bom-lookup.up.railway.app`, or attach a custom domain. If the hostname differs,
   edit the URL in `integrations/openai-mcp/mcp.json` and rebuild the ZIP. Start-up syncs
   the advisory database first, 70 to 150 seconds in tests.
5. Check the deployment:

   ```bash
   HOST=https://agent-bom-lookup.up.railway.app
   curl -s $HOST/health          # public_readonly true, auth_required false, tool_count 2
   curl -s $HOST/.well-known/mcp/server-card.json | python -m json.tool | head -40
   curl -s -o /dev/null -w '%{http_code}\n' $HOST/.well-known/oauth-protected-resource   # 404
   ```

6. Verify the client address. From one machine, send 31 `tools/call` requests for
   `intel_lookup`, each with a different made-up `X-Forwarded-For` value: the 31st must
   return a rate-limit error. If it does not, set the hops to `0` and repeat. Then confirm
   that a second network (for example a phone hotspot) is not limited at the same time;
   if it is, every caller shares one budget and the hops value is too low.
7. In the [Plugins](https://platform.openai.com/plugins) dashboard, select **Upload new or
   existing plugin**, choose the verified identity, and upload
   `dist/agent-bom-openai-mcp-plugin.zip` as a new plugin. Do not upload it over the
   Route A draft.
8. Under **MCPs**, open the server, check the URL, choose **No authentication**, and start
   **Verify Domain**. Put the token the portal shows in `AGENT_BOM_OPENAI_APPS_CHALLENGE`
   on the Railway service, redeploy, check that
   `curl -s $HOST/.well-known/openai-apps-challenge` prints only the token, then select
   **Verify Domain**. Connect, and wait for the tool scan to list exactly `check` and
   `intel_lookup`.
9. Before submitting, extend `site-docs/privacy.md` and `site-docs/terms.md` for the hosted
   lookup service: the operator's name, contact address, governing law, platform log
   retention, and the facts in [PERMISSIONS](PERMISSIONS.md#public-lookup-server). The
   notice now says the project offers no hosted service, which would be false.
10. Record a demo of the five positive and three negative cases from `plugin.json` in
    ChatGPT, on desktop and mobile, and host it. Enter its URL in **Review details**.
11. In **Review details**, paste the annotation justifications above. There is no test
    account; say the server needs no sign-in.
12. Select **Submit for review**, accept the attestations, and publish after approval.

The existing OAuth service's `railway.json` is config as code, which Railway stops
reading on 2026-12-01. Before then, migrate that service (`railway config migrate`) or
set its Dockerfile path in the dashboard; otherwise it may build the root `Dockerfile`
instead of `deploy/docker/Dockerfile.sse`.

## Only the owner can do these

- Portal submissions in both directories, and the attestations.
- Cutting the release.
- OpenAI identity verification, and contact with an OpenAI representative.
- Approving the legal pages and naming the operator, contact address, law and retention.
- Any hosted deployment: Keycloak configuration, subject allowlist, reviewer account, domain
  token, a public lookup service.
- Recording and hosting the video.

## Demo video script (about 3 minutes)

Use the demo project only, with notifications off and a fresh account or terminal. Show
nothing else on screen.

1. **0:00** Title: "agent-bom: security checks for your AI setup". Say it runs locally, needs
   no account, and changes nothing without asking.
2. **0:15** Create the demo project with `scripts/plugin_review_fixture.py`, and open the
   session there.
3. **0:30** "Is event-stream@3.3.6 from npm safe to install?" Show the do-not-install verdict
   and the advisory id.
4. **0:55** "Audit the MCP servers configured in this folder." Show the unpinned launcher, the
   token name without its value, and the plain-HTTP server. Point out the servers were not started.
5. **1:25** "Are the skills in .claude/skills safe to use?" Show the malicious verdict, and that
   the instructions were not followed.
6. **1:50** "Am I affected by CVE-2024-3651? Check this project." Show idna 3.6 and the fix.
7. **2:10** Negative: "Use agent-bom to review my past sessions." Show the refusal.
8. **2:25** Claude only, with the guard: ask it to run `pip install reqeusts`. Show the block
   naming `requests`, and that nothing was installed.
9. **2:45** Show the README's list of what is read and sent. End.
