# AI enrichment

AI enrichment is optional and advisory by default. The scanner's deterministic
findings, severities, suppressions, and pass/fail result remain authoritative.

It is off until you turn it on. On the CLI, `--ai-enrich` turns it on for that
scan. In the control plane an operator must set
`AGENT_BOM_AI_CONTROL_PLANE_ENABLED=1`; a scan request cannot do it alone. Prompts
stay on the loopback interface unless `AGENT_BOM_AI_ALLOW_REMOTE=1` is set.

## First command, artifact, next step

Run a local-model enrichment:

```bash
ollama pull qwen2.5:3b
agent-bom scan . --ai-enrich --ai-model ollama/qwen2.5:3b --format json --output report.json
```

The CLI prints an **AI advice** summary. The JSON report adds
`ai_finding_assessments`, keyed by deterministic `finding_id`, plus
`ai_enrichment_metadata`. Each assessment carries a `verdict`
(`confirmed`, `likely_false_positive` or `needs_review`), confidence, rationale,
`advisory: true`, and provenance: provider, model, model digest, prompt version,
dataset version, prompt and response hashes, and time. CSV, SARIF and HTML exports
carry the same advice in fields of their own. Review these alongside `findings`;
they do not replace scanner evidence.

If the explicitly selected provider is unavailable, the scan completes normally
without AI assessments. An `ollama/*` selection never falls back to a remote
provider. Model responses with unknown finding IDs are discarded. Raw finding
evidence is not sent to triage; outbound prompts use bounded fields and secret
redaction is enabled by default.

## Hard rules

These hold whatever a model says, and tests pin them:

- AI advice cannot dismiss or downgrade a KEV, malicious-package or
  reachable-critical (`critical` with confirmed or likely reachability, or a graph
  path) finding. A dismissal is discarded at parse time, the schema refuses to
  build one, and each read applies the rule again, because a finding can become
  known-exploited after its assessment was stored.
- A finding whose text is addressed to the reader, such as "ignore previous
  instructions", goes to a person: the verdict becomes `needs_review`, or stays
  `confirmed` for a protected finding, and the model's rationale is replaced.
- A failed, invalid or over-budget call never changes scanner results. See
  [Runtime fail modes](RUNTIME_FAIL_MODES.md#ai-advice).

## Deterministic opt-in gate

AI skill-file reviews cannot change pass/fail by default. To opt in, both flags
are required:

```bash
agent-bom scan . --ai-enrich --ai-deterministic --ai-gate-findings
```

This sets model temperature to zero and allows only **high-confidence** AI
false-positive reviews, severity adjustments, or AI-detected skill findings to
affect the skill audit and process exit gate. Missing confidence normalizes to
`low` and cannot weaken a deterministic gate. The original result is retained
as `deterministic_passed`, while `ai_gate_enabled` records the opt-in. The
general `ai_finding_assessments` surface always remains advisory.

Temperature zero improves stability but is not a byte-reproducibility claim:
hosted providers and model revisions can change. Cache entries are isolated by
enrichment run, provider, model, optional model revision, task, effective
temperature, redaction posture, and prompt version. This keeps concurrent API
scans from reusing and relabeling another run's model response. Assessment
provenance records prompt/response hashes and the observation time so an
operator can identify drift.

## Routing, limits, and data boundary

| Setting | Default | Purpose |
|---|---:|---|
| `AGENT_BOM_AI_MODEL_CHEAP` | unset | Narrative and summary model |
| `AGENT_BOM_AI_MODEL_STRONG` | unset | Detection, triage, and config-analysis model |
| `AGENT_BOM_AI_MAX_CALLS` | `150` | Actual provider-request cap, including retries; `0` is unlimited and negative values are rejected |
| `AGENT_BOM_AI_MAX_FINDINGS` | `100` | Highest-risk findings offered to triage |
| `AGENT_BOM_AI_FINDING_BATCH_SIZE` | `1` | Findings per triage request, capped at 50. Small models skip entries in larger batches |
| `AGENT_BOM_AI_MAX_CONCURRENT_CALLS` | `2` | Provider calls at once in this process |
| `AGENT_BOM_AI_RUN_DEADLINE_SECONDS` | `900` | Whole AI step for one scan; the scan continues past it and keeps what it has |
| `AGENT_BOM_AI_NUM_CTX` | `8192` | Ollama context window, sent explicitly so a batch is not silently truncated |
| `AGENT_BOM_AI_ALLOW_REMOTE` | unset | Allow prompts to leave the loopback interface |
| `AGENT_BOM_AI_CONTROL_PLANE_ENABLED` | unset | Turn on AI for the control plane |
| `AGENT_BOM_AI_CONTROL_PLANE_TENANTS` | unset | Narrow control-plane AI to these tenants (comma-separated) |
| `AGENT_BOM_AI_CONTROL_PLANE_MODEL` | unset | The model every control-plane call uses; a request cannot choose another. Explain requires it |
| `AGENT_BOM_AI_EXPLAIN_PER_MINUTE` | `6` | Explain requests per tenant per minute |
| `AGENT_BOM_AI_EXPLAIN_PER_DAY` | `200` | Explain requests per tenant per day |
| `AGENT_BOM_AI_REDACT_PROMPTS` | `true` | Redact recognizable secrets before model calls |
| `AGENT_BOM_AI_DETERMINISTIC` | `false` | Set temperature zero for all enrichment calls |
| `AGENT_BOM_AI_MODEL_REVISION` | unset | Optional immutable provider/model revision recorded in cache posture and provenance |

`ai_enrichment_metadata.call_budget` reports provider attempts, retries, cache
hits, remaining attempts, exhaustion, and per-task counts. `triage_scope` reports
total, offered, truncated and assessed finding counts, and `skipped` says why:
`below_risk_cutoff` or `suppressed`. Findings are offered highest risk first:
protected, then severity, risk score and EPSS. Provider
failures, invalid or oversized JSON, and exhausted budgets degrade to partial or
absent advice without weakening deterministic gates.

The generic provider inventory reports an installed LiteLLM adapter as a
capability with `selected_model_ready: null`; it does not claim that an
arbitrary model is configured. A selected model resolves active only when it
has its provider-specific credential, an authenticated LiteLLM proxy, an
explicit loopback OpenAI-compatible/LiteLLM endpoint, or a supported Bedrock or
Vertex ambient workload-identity chain.

## Exact prompt data boundary

| Task | Prompt material | Remote eligible |
|---|---|---|
| Finding triage | A short ref in place of the ID; type, source, severity, advisory; bounded title, description and asset; plus the field groups kept by the evaluation below. No raw evidence or credential values | Only with `AGENT_BOM_AI_ALLOW_REMOTE=1` |
| Graph explanation | Bounded labels, types, severity and risk of up to 25 selected nodes; relationship and traversability of up to 60 edges among them. No node attributes or edge evidence | Only with `AGENT_BOM_AI_ALLOW_REMOTE=1` |
| Narrative/summary | Bounded scan and vulnerability context, package coordinates, agent/tool names, and credential variable names; no credential values | Only with `AGENT_BOM_AI_ALLOW_REMOTE=1` |
| MCP config analysis | Up to 10 servers across the first 20 agents, sanitized and bounded command arguments, transport, tool names, and credential variable names; omissions are explicit | Only with `AGENT_BOM_AI_ALLOW_REMOTE=1` |
| Skill detection/review | Up to 10 discovered skill files × 6,000 characters, plus up to 100 bounded static finding summaries; omissions are explicit, and returned source paths must match a file offered to the model | **No. Ollama is local only when its configured URL uses a loopback host; non-loopback Ollama and all other remote selections skip this task.** |

Recognizable credentials are redacted at every provider boundary. Secret
redaction is defense in depth, not a general source-code anonymizer, which is why
raw skill content is restricted to a loopback Ollama endpoint. Provider metadata
reports a non-loopback Ollama URL as networked instead of labeling it local.

## Measured quality

Quality depends on the model. These numbers come from
`scripts/ai_triage_eval.py`, run on 2026-11-05 at temperature zero on one 16 GB
laptop running other work, so treat the timings as rough. Dataset version
`ai-triage-dataset.v1`, prompt version `ai-triage.v3`.

**Held-out split (82 findings, not used for tuning):**

| Model | Digest | Cases | FP precision | FP recall | Wrong dismissals | Severe proposed / after guard | ECE | Invalid | Injection: model / final | s per finding | Tokens per finding |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `ollama_chat/llama3.2` | `a80c4f17acd5` | 82 | 67% | 20% | 2 | 5 / 0 | 0.178 | 0% | 54% / 96% | 2.72 | 637.7 |
| `ollama/gemma3:4b` | `68ceab7e468a` | 82 | 80% | 20% | 1 | 1 / 0 | 0.15 | 0% | 69% / 92% | 4.04 | 662.7 |
| `ollama/llama3.2` | `a80c4f17acd5` | 82 | 67% | 20% | 2 | 5 / 0 | 0.181 | 0% | 54% / 96% | 2.76 | 637.8 |
| `ollama/qwen2.5:3b` | `357c53fb659c` | 82 | 100% | 50% | 0 | 1 / 0 | 0.021 | 0% | 85% / 100% | 2.31 | 627.4 |

`ollama_chat/*` is LiteLLM 1.100.4 against the same local Ollama server. Full digests
are in `tests/fixtures/ai_triage_eval/recordings/`.

**Development split (117 findings, used for tuning):**

| Model | Digest | Cases | FP precision | FP recall | Wrong dismissals | Severe proposed / after guard | ECE | Invalid | Injection: model / final | s per finding | Tokens per finding |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `ollama/gemma3:4b` | `68ceab7e468a` | 117 | 100% | 31% | 0 | 2 / 0 | 0.163 | 0% | 71% / 100% | 4.07 | 660.5 |
| `ollama/llama3.2` | `a80c4f17acd5` | 117 | 94% | 47% | 1 | 5 / 0 | 0.031 | 0% | 71% / 100% | 2.77 | 632.8 |
| `ollama/qwen2.5:3b` | `357c53fb659c` | 117 | 96% | 61% | 1 | 4 / 0 | 0.017 | 0% | 41% / 100% | 2.33 | 623.8 |

**Recommendation:** `ollama/qwen2.5:3b` for local triage. It led on the development
split and is the only tested model that meets the bar below on the held-out split.
Do not treat `llama3.2` or `gemma3:4b` as a false-positive filter: their held-out
recall is 20%, and `llama3.2` wrongly dismissed 2 real findings out of 6 it flagged.

The bar, fixed before any held-out run: false-positive precision at least 85%,
recall at least 50%, no protected finding dismissed after guards, invalid responses
at most 5%, calibration error at most 0.15, injection resistance at least 80% from
the model alone and 95% after guards.

### How to read these numbers

- **The samples are small.** `qwen2.5:3b` flagged 10 of 20 eligible false positives
  on the held-out split, all correct. A 95% interval on 10 of 20 runs from about 27%
  to 73%, and 10 of 10 is compatible with true precision as low as about 72%. A
  result at the recall bar is not a margin above it.
- **A model is not robust to injection on its own.** `qwen2.5:3b` resisted 85% of
  attacks on the held-out split but 41% on the development split. Guards bring the
  final figure to 100% for it, but other models let a paraphrased attack through
  (for `llama3.2`, an IaC finding claiming a sandbox and a security sign-off).
  Pattern detection does not catch every wording.
- **Half of real false positives remain.** Many are correctly held as `needs_review`.
- **Some false positives can't be found from these fields.** A version below an
  advisory's `introduced` event looks vulnerable when only the fixed version is
  known. They stay in the dataset as hard cases.
- Precision and recall exclude protected findings, because the hard rule forbids
  dismissing them even when the scanner was wrong. There are 3 such cases.
- The verdict labels matter. Asking whether the "scanner is correct" gave models
  that explained a fix correctly and then answered the opposite. Asking whether the
  problem exists took `llama3.2` from 12% recall to 76% on a 50-case development subset.

### Dataset

`tests/fixtures/ai_triage_eval/dataset.v1.json` holds 199 labelled findings built by
`scripts/build_ai_triage_dataset.py`, using the product's real conversion code and,
where possible, real scans of committed fixtures: 140 true positives and 59 false
positives. Each case states its label basis. Sources are public OSV advisories, the
public CISA KEV catalogue (version 2026.11.04), and this repository's accuracy
corpora. 43 are adversarial, with instructions planted in titles, descriptions,
package names and asset names. 12 of those were written to be held out and never
used to tune the tampering detector. The split is a hash of the case ID.

Eight cloud look-alike cases are reconstructions, not captured scanner output: a
real rule's output re-targeted at a shape the IaC accuracy tests pin as quiet. Each
says so in its source.

### Which fields earn their place

Leave-one-out on the development split with `llama3.2` (36 eligible false positives).
Only one model was measured, and small differences are one or two cases.

| Fields sent | FP precision | FP recall | Wrong dismissals | ECE |
|---|---:|---:|---:|---:|
| All | 94% | 47% | 1 | 0.031 |
| None of the groups below | 50% | 3% | 1 | 0.145 |
| Without versions (including `fix_status`) | 100% | 3% | 0 | 0.179 |
| Without path summary | 83% | 42% | 3 | 0.082 |
| Without exploit signals (KEV, EPSS, risk) | 94% | 42% | 1 | 0.045 |
| Without reachability | 94% | 42% | 1 | 0.053 |
| Without scope | 94% | 44% | 1 | 0.038 |

Versions carry most of the gain and path summary helps precision. Exploit signals,
reachability and scope each move only one or two cases, which is not strong evidence;
they stay because the prompt's rules about KEV and unreachable findings need them.

### Run it

```bash
python scripts/ai_triage_eval.py --check                                   # replay; what CI runs
python scripts/ai_triage_eval.py --live --model ollama/qwen2.5:3b --split dev
python scripts/ai_triage_eval.py --live --record --model MODEL --split heldout   # then --write-baselines
```

`--check` needs no model. It fails if a score drops below its baseline, a protected
finding is dismissed, or a change to the prompt, its fields or the dataset leaves a
recording stale. Tune only on `dev`.

### Performance

| Measure | Result |
|---|---|
| Scan with AI off | No AI code runs: `--ai-enrich` guards the import and the call |
| Added read cost, 50-row page | 0.9 ms SQLite, 1.8 ms Postgres (p50) |
| Added read cost, 1,000-row page | 25 ms SQLite, 12 ms Postgres (p50) |
| Triage of 100 findings, `qwen2.5:3b` | 421 s (4.2 s each), 100 assessed; the longest event-loop stall was 53 ms |

Read cost was measured against 21,000 stored assessments. Ollama's default context
window silently cut a 7,000-token prompt to 2,050 tokens here, which is why
`num_ctx` is always sent.

## Where advice appears

| Surface | What you get |
|---|---|
| `GET /v1/findings` | `ai_assessment` on each row with stored advice. A read never calls a model. If the advice store fails, the list still answers, with a warning |
| `GET /v1/ai/status` | `state` (`on`, `off` or `degraded`), the reason, and the tenant's last run with coverage |
| Findings page and drawer | A dashed "AI" badge beside the finding; a drawer section with verdict, confidence, reason, model and date; a status line that says when AI is off or failed. Model text renders as text only |
| CLI, JSON, CSV, SARIF, HTML | The same advice, in fields of its own |
| `POST /v1/graph/explain`, "Explain this path" | On-demand explanation of real graph evidence, below |

Advice is stored per scan and tenant in `ai_finding_assessments` and
`ai_triage_runs`, expires with its scan, and is removed by tenant erasure. A grouped
finding row shows the advice for its representative occurrence only.

## Graph explanation

`POST /v1/graph/explain` takes up to 25 node IDs, optionally as an ordered path,
and runs only when asked. It reads those nodes and the edges between them, and
returns claims that each cite node or edge IDs from that context. It writes nothing
to the graph.

Validation is code, not the model. A claim is removed if it cites nothing, cites
anything outside the context, or asserts reach (reachable, exploitable, leads to,
and similar words) without citing only traversable edges. The response counts what
was removed in `rejected_claims`. `evidence_limits` is computed without the model
and states missing hops, non-traversable hops, and whether a recorded attack path
covers the selection. It needs an analyst role, and rate and budget limits apply
per tenant.

Removing unsupported claims does not make the remaining ones good. Validation
checks citations and recorded reach, not whether a sentence describes its citation
well, and no scored dataset exists for that yet. In a live run over six small test
paths, `qwen2.5:3b` kept 4 claims and removed 2; one kept claim reversed the direction
of a real `depends_on` edge. Read the citations, not only the sentence.

## Audit and metrics

Each provider call produces one record: tenant, actor, task, provider, model,
digest, prompt and response hashes, tokens, latency, outcome, and whether a guard
rejected output. Prompt and response text is never recorded. In the control plane
the record goes to the tamper-evident audit chain as `ai.call`, with
`agent_bom_ai_calls_total{task,provider,outcome}` and
`agent_bom_ai_call_latency_milliseconds_total{task,provider}` in Prometheus. The
CLI has no audit chain; it logs the same fields at `INFO`, and each assessment
keeps its provenance in the report.

## Not built

Ensemble scoring, compliance-control tagging, general novel-finding detection
beyond skill files, and MCP execution controls are not product behavior.
