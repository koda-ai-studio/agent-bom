# AI eval coverage

`agent-bom` reads the eval suites committed with a project, links each one to
the agent or model it tests, and raises a governance finding for agents with
high-risk capabilities that no safety or red-team eval is linked to.

Eval detection runs as part of the AI-inventory source scan
(`agent-bom scan --ai-inventory <path>`, and automatically when a project has a
Python AI surface). It only reads files: configs are parsed with
`yaml.safe_load`, Python with `ast`. Nothing is imported, executed or sent
anywhere.

## Supported harnesses

| Harness | Detected from | Purpose is `safety` when | Purpose is `quality` when | Target linking |
|---|---|---|---|---|
| promptfoo | `promptfooconfig.{yaml,yml,json}`, `redteam.{yaml,yml}` | a `redteam` section, or `moderation` / `is-refusal` / `guardrails` assertions | other assertion types | `targets` / `providers`: `file://<entry>.py` (and a thin provider file's project imports) link to the agents defined there; `vendor:model` ids link to the model; HTTP and command targets stay unlinked |
| deepeval | Python importing `deepeval` / `deepteam` | `BiasMetric`, `ToxicityMetric`, `PIILeakageMetric`, `RoleViolationMetric`, `MisuseMetric`, `NonAdviceMetric`, or deepteam red-teaming | RAG, agentic and G-Eval metrics | `LLMTestCase(actual_output=...)` and `model_callback=` resolved to a project agent; a metric's judge `model=` is never a target |
| ragas | Python importing `ragas` | `harmfulness` / `maliciousness` critiques | faithfulness, answer relevancy, context precision/recall and similar | none: a ragas run scores a dataset, so the suite is unlinked |
| Inspect | `@task` functions from `inspect_ai` | the task builds on an `inspect_evals` safety benchmark (agentharm, strong_reject, wmdp, xstest, cyberseceval, ...) | — | `eval(task, model=...)` and `Task(model=...)` link the model; `Task(solver=...)` resolved to a project agent |
| OpenAI evals | registry YAML under `registry/evals/`, `client.evals.create(...)` | — | `evals.elsuite.basic.*` match classes | none: the completion function is chosen at run time |
| LangSmith | `evaluate()` / `client.evaluate()` / `aevaluate()` and `create_dataset()` | — | — | the evaluated target (first argument or `target=`) resolved to a project agent |

Anything the files do not show stays `unknown`; purpose is never guessed from a
name. A target the files name but the scan cannot resolve stays on the suite
with `unresolved_reason`, and the suite is reported `unlinked`.

A Python reference resolves when it is a name the eval imports from a project
module that defines a framework agent, a module-level value built from one
(`graph = builder.compile()`), or a local function or variable that calls one.

Results are attached only when a run wrote them into the project: promptfoo
JSON written to the config's `outputPath` (`stats.successes`, `failures`,
`errors` and `timestamp`). Each result names its source file and recorded date.

## Safety-eval coverage finding

`EVAL_COVERAGE_GAP` (source `EVAL_SCAN`, rule `eval-coverage/safety-gap`) is
raised for a framework agent when all of these hold:

1. Eval detection ran to completion over the project scope that contains the
   agent. A search stopped by its limit (2,000 candidate eval files or 20,000
   files read) or a report without eval coverage raises nothing.
2. The agent has at least one high-risk signal, from the capability
   classification the scanner already applies to tools:
   - **write/exec tools** — a tool classified WRITE, DELETE, EXECUTE or ADMIN;
   - **credentials** — a credential env var read in the agent's file, other
     than the model-provider and tracing keys the agent uses to call its own
     model (for example `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`,
     `LANGSMITH_API_KEY`), or a tool classified AUTH;
   - **data access** — a vector-store SDK found in the agent's own file.
3. No eval with purpose `safety` is linked to the agent, or to an agent that
   contains it or delegates to it (a red-team eval on a LangGraph graph covers
   the graph's nodes).

| Threshold | Severity |
|---|---|
| write/exec tools present | `medium` |
| credentials or data access only | `low` |

This is a governance severity. The finding is excluded from the CVE counts and
from the `--fail-on-severity` / `--warn-on` gates, so it never changes the
vulnerability verdict or the exit code. It appears in JSON, SARIF, HTML, the
API (`/v1/findings`) and the dashboard.

The finding says what was searched — "no safety eval found in the scanned
project files", the scope and the number of candidate files read — and never
claims the agent has never been evaluated. Its evidence lists the risk signals,
the evals linked to the agent with their results, safety evals that target the
agent's model only (they do not exercise its tools), and safety evals in the
project that could not be linked to any agent.

Compliance mapping: NIST AI RMF `MEASURE-2.6` (evaluated regularly for safety
risks) and `MEASURE-2.7` (security and resilience evaluated). No other control
is claimed.

**Remediation:** commit a safety or red-team eval that targets the agent — for
example a promptfoo config with a `redteam` section whose target is the agent's
entry file, or a deepeval test that scores the agent's output with safety
metrics. If one already exists, point its target at the agent so the scan can
link it.

## Graph and dashboard

Each suite is an `eval_suite` node; `evaluates` edges (governance, not
traversed by attack paths) link it to the agents and models it targets. A
framework agent folded into the project agent is represented by that agent.
Agent nodes carry `eval_coverage` (`assessed`, `safety_suites`, linked suites
with results). The agent architecture view shows an agent's evals in its detail
panel, and the finding drawer shows the coverage evidence.
