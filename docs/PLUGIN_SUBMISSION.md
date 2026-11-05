# Submitting the agent-bom plugins

**Do not submit yet.** The plugins pin agent-bom 0.113.2, which has known critical
bugs fixed only on `main`, and its audit profile still offers `agent_activity`, the
chat-history tool that the Claude directory policy forbids. Cut a release first.

```bash
make plugin-submission-check
```

This fails while any pin is below the release floor, either legal page is a draft, or
review cases are missing. It is not part of `make preflight`, because it stays red until
the steps below are done.

Rules change. Reread the linked pages before submitting; they were last checked on
2026-11-05.

## What is ready, with evidence

| Requirement | Status | Evidence |
|---|---|---|
| Name, version, description, author, license, icon | Ready | `claude plugin validate --strict --profile directory` passes on both Claude plugins; `scripts/build_codex_plugin_zip.py` checks the OpenAI limits |
| Skill frontmatter and least-privilege tool lists | Ready | `tests/test_claude_code_plugin.py` |
| Tool annotations match the code | Ready on `main`, not in 0.113.2 | `tests/test_plugin_directory_readiness.py`, [table](PERMISSIONS.md#plugin-hook-and-tool-hints) |
| No chat history access | Ready on `main`, **fails in 0.113.2** | Discovery test with planted session files; the pinned audit profile still lists `agent_activity` |
| Network destinations disclosed | Ready | `tests/test_plugin_egress_hosts.py`, [PERMISSIONS](PERMISSIONS.md) |
| Hook disclosure | Ready | Guard [README](../integrations/agent-bom-guard/README.md) and [privacy page](../site-docs/privacy.md) |
| Repository limits (Claude) | Ready, close to one limit | About 8,800 files and folders against a limit of 10,000; 32 MiB archive against 50 MiB. Recheck before each submission |
| Review cases | Written and run | [PLUGIN_REVIEW_CASES.md](PLUGIN_REVIEW_CASES.md) |

Evals on 2026-11-05 (branch code with recorded tool output, one run of each of 18 cases, no
baseline, about $3.69 list price): 17 cases scored 1.0. `bom-cyclonedx` scored 0.8 on its
judged report grader, and failed that grader in 1 of 3 more runs (it also passed in an earlier run);
the answers read as correct but framed counts differently from the rubric. The full run of
three with a baseline has not been done.

## Steps for both directories

1. Merge the open fix work and cut the release (`scripts/bump-version.py`). This moves
   the versions, skill pins and `uv.lock`.
2. Review `site-docs/privacy.md` and `site-docs/terms.md`, fill in the operator, contact
   address, law and retention, and remove the draft notes. Only the owner can do this.
3. Run `make plugin-submission-check`, and fix what it reports.
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
   path `integrations/claude-code`, tracked branch or tag: the release.
2. Select **Validate**. Fix anything marked **Blocks**, then **Re-validate**.
3. Expect two holds, which are not rejections: **Runs a pinned npx or uvx package** on the
   `uv run --frozen` launcher, and **Scripts the validator couldn't follow** on the guard's
   Python hook. The guard README has a section for the reviewer.
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
server added later; an MCP version would be a new plugin.

### Route A: skills-only, desktop-only (ready after the release)

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

### Route B: remote MCP (not possible today)

| Requirement | Today |
|---|---|
| Public HTTPS endpoint | `https://agent-bom-mcp.up.railway.app/mcp` runs 0.113.2, `scan` profile, 8 tools |
| No auth, or OAuth | OAuth only. Anonymous `tools/list` returns 401, and `public_readonly` is false |
| Public lookup without login | **Not deployed.** The code exists (`--public-readonly`: `check` and `intel_lookup`), but startup refuses it together with OAuth, so it needs its own deployment and hostname |
| Sign-in for the public | No. OAuth admits only subjects in `AGENT_BOM_MCP_OAUTH_SUBJECTS`, and one fixed tenant |
| Reviewer account | None. OpenAI needs a sample-data login with no MFA |
| `openid` and `email` scopes, UserInfo | The issuer has them. The resource metadata advertises only `read`, and tenant binding is untested with them |
| Domain verification | Not done. `/.well-known/openai-apps-challenge` returns 404, and serving the token needs a code or proxy change |
| Package with `mcp.json` | None exists |
| Tools useful on a server | `scan`, `remediate` and others read the server's own disk, not the user's. Only lookups make sense remotely |

The honest narrow option is a separate public deployment serving `check` and `intel_lookup`
under its own hostname, as a new plugin. That is a product decision for the owner.

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
