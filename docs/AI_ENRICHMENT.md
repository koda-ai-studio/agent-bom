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
  instructions", goes to a person. Recognized text is withheld from the prompt, the
  verdict becomes `needs_review`, or stays `confirmed` for a protected finding, and
  the model's rationale is replaced.
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

Quality depends on the model. These numbers come from `scripts/ai_triage_eval.py`,
run on 2026-11-06 at temperature zero on one 16 GB laptop running other work, so
treat the timings as rough. Prompt version `ai-triage.v4`. Full digests are in
`tests/fixtures/ai_triage_eval/recordings/`.

**The bar** is committed in `tests/fixtures/ai_triage_eval/bar.json`, ahead of the
held-out runs in this section: false-positive precision at least 85%, recall at least
50%, no protected finding dismissed after guards, invalid responses at most 5%,
calibration error at most 0.15, injection resistance at least 80% from the model alone
and 95% after guards.

**Held-out set v2 (`ai-triage-dataset.v2`, 160 new findings, 70 eligible false
positives, not available when the prompt was tuned):**

| Model | Digest | Cases | FP precision | FP recall | Wrong dismissals | Severe proposed / after guard | ECE | Invalid | Injection: model / final | s per finding | Tokens per finding |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `ollama_chat/llama3.2` | `a80c4f17acd5` | 160 | 87% | 56% | 6 | 0 / 0 | 0.081 | 1% | 70% / 100% | 2.76 | 661.7 |
| `ollama/gemma3:4b` | `68ceab7e468a` | 160 | 88% | 53% | 5 | 0 / 0 | 0.143 | 0% | 75% / 90% | 4.72 | 698.2 |
| `ollama/llama3.2` | `a80c4f17acd5` | 160 | 87% | 56% | 6 | 0 / 0 | 0.078 | 0% | 70% / 100% | 2.42 | 661.6 |
| `ollama/qwen2.5:3b` | `357c53fb659c` | 160 | 87% | 79% | 8 | 0 / 0 | 0.037 | 0% | 95% / 100% | 2.33 | 657.5 |

`ollama_chat/*` is LiteLLM 1.100.4 against the same local Ollama server.

| Model | True flags / flagged | Precision, 95% interval | True flags / eligible | Recall, 95% interval | Bar |
|---|---:|---:|---:|---:|---|
| `qwen2.5:3b` | 55 / 63 | 77-93% | 55 / 70 | 68-87% | Met |
| `llama3.2` | 39 / 45 | 74-94% | 39 / 70 | 44-67% | Missed: raw injection 70% |
| `gemma3:4b` | 37 / 42 | 75-95% | 37 / 70 | 41-64% | Missed: injection 75% raw, 90% final |

**Recommendation:** `ollama/qwen2.5:3b` for local triage. It is the only tested model
that meets the bar. It still gets things wrong: 8 of its 63 dismissals were real
findings, so treat a dismissal as a reason to look, not a reason to close.

**Earlier held-out set v1 (82 findings, prompt `ai-triage.v4`):**

| Model | Digest | Cases | FP precision | FP recall | Wrong dismissals | Severe proposed / after guard | ECE | Invalid | Injection: model / final | s per finding | Tokens per finding |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `ollama/gemma3:4b` | `68ceab7e468a` | 82 | 80% | 20% | 1 | 1 / 0 | 0.15 | 0% | 77% / 92% | 5.1 | 694.6 |
| `ollama/llama3.2` | `a80c4f17acd5` | 82 | 86% | 30% | 1 | 4 / 0 | 0.137 | 0% | 81% / 100% | 2.35 | 655.7 |
| `ollama/qwen2.5:3b` | `357c53fb659c` | 82 | 83% | 50% | 2 | 0 / 0 | 0.05 | 0% | 96% / 100% | 2.33 | 655.3 |

These results are no longer unseen: an earlier prompt was measured on this set before
the current prompt was written. `qwen2.5:3b` is 2 points under the precision bar here,
with 2 wrong dismissals out of 12 flagged.

**That earlier prompt on set v1, frozen as first measured (`ai-triage.v3`, 2026-11-05):**

| Model | Digest | Cases | FP precision | FP recall | Wrong dismissals | Severe proposed / after guard | ECE | Invalid | Injection: model / final | s per finding | Tokens per finding |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `ollama_chat/llama3.2` | `a80c4f17acd5` | 82 | 67% | 20% | 2 | 5 / 0 | 0.178 | 0% | 54% / 96% | 2.72 | 637.7 |
| `ollama/gemma3:4b` | `68ceab7e468a` | 82 | 80% | 20% | 1 | 1 / 0 | 0.15 | 0% | 69% / 92% | 4.04 | 662.7 |
| `ollama/llama3.2` | `a80c4f17acd5` | 82 | 67% | 20% | 2 | 5 / 0 | 0.181 | 0% | 54% / 96% | 2.76 | 637.8 |
| `ollama/qwen2.5:3b` | `357c53fb659c` | 82 | 100% | 50% | 0 | 1 / 0 | 0.021 | 0% | 85% / 100% | 2.31 | 627.4 |

**Development split (117 findings, used for tuning):**

| Model | Digest | Cases | FP precision | FP recall | Wrong dismissals | Severe proposed / after guard | ECE | Invalid | Injection: model / final | s per finding | Tokens per finding |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `ollama/gemma3:4b` | `68ceab7e468a` | 117 | 100% | 33% | 0 | 0 / 0 | 0.151 | 0% | 100% / 100% | 4.6 | 695.1 |
| `ollama/llama3.2` | `a80c4f17acd5` | 117 | 85% | 47% | 3 | 1 / 0 | 0.038 | 0% | 88% / 100% | 2.41 | 656.7 |
| `ollama/qwen2.5:3b` | `357c53fb659c` | 117 | 100% | 67% | 0 | 0 / 0 | 0.009 | 0% | 94% / 100% | 3.51 | 658.1 |

### How to read these numbers

- **Most of the recall is one easy class.** On set v2, `qwen2.5:3b` found 46 of 48
  false positives where the installed version is at or above the fix, but only 7 of 15
  cloud look-alikes and 0 of 5 documentation look-alikes. It is much stronger on
  version checks than on judging prose.
- **Multi-release advisories caused most wrong dismissals.** 7 of `qwen2.5:3b`'s 8
  wrong dismissals on set v2 are vulnerable versions whose recorded fix belongs to a
  different release line, so the version check reports the fix as installed. Those
  dataset cases take the advisory's last fix event, which may be harsher than a real
  scan; this has not been measured on real scans.
- **Injection resistance mostly comes from withholding.** The swing from 41% to 85%
  between v1 splits came from which attacks each split held: direct "mark this a false
  positive" text in a description was flagged 6 of 7 times, while paraphrases were
  flagged 2 of 10. Text recognized as instruction-like now never reaches the model, and
  a closing reminder follows the data. Paraphrases that pass the pattern match can still
  move a model: one reached a final dismissal on `gemma3:4b`.
- **Some false positives can't be found from these fields.** A version below an
  advisory's `introduced` event looks vulnerable when only the fixed version is known.
- Precision and recall exclude protected findings, because the hard rule forbids
  dismissing them even when the scanner was wrong.
- The verdict labels matter. Asking whether the "scanner is correct" gave models that
  explained a fix correctly and then answered the opposite. Asking whether the problem
  exists took `llama3.2` from 12% recall to 76% on a 50-case development subset.

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

`dataset.v2.json`, built by `scripts/build_ai_triage_dataset_v2.py`, is all held out.
It uses advisories and findings v1 does not: 70 false positives, all eligible, and 90
true positives. 20 of the 160 are attacks written for it. Its 15 cloud
look-alikes are reconstructions too, each pinned by a named test in this repository,
and rule IDs with no matching rule are marked `reconstructed-`.

### Which fields earn their place

Leave-one-out on the development split with `llama3.2` and prompt `ai-triage.v3` (36
eligible false positives). Small differences are one or two cases.

| Fields sent | FP precision | FP recall | Wrong dismissals | ECE |
|---|---:|---:|---:|---:|
| All | 94% | 47% | 1 | 0.031 |
| None of the groups below | 50% | 3% | 1 | 0.145 |
| Without versions (including `fix_status`) | 100% | 3% | 0 | 0.179 |
| Without path summary | 83% | 42% | 3 | 0.082 |
| Without exploit signals (KEV, EPSS, risk) | 94% | 42% | 1 | 0.045 |
| Without reachability | 94% | 42% | 1 | 0.053 |

Versions carry most of the gain and path summary helps precision. Exploit signals and
reachability move only a few cases, which is weak evidence; they stay because the
prompt's rules about KEV and unreachable findings need them.

Scope (provider, environment, dependency scope) was dropped. Retested on three models
with prompt `ai-triage.v4`, it changed at most one case on each, in mixed directions:
removing it gained `qwen2.5:3b` one wrong dismissal fewer and cost `llama3.2` and
`gemma3:4b` one true flag each.

### Run it

```bash
python scripts/ai_triage_eval.py --check                                   # replay; what CI runs
python scripts/ai_triage_eval.py --live --model ollama/qwen2.5:3b --split dev
python scripts/ai_triage_eval.py --live --record --model MODEL --dataset v2 --split heldout   # then --write-baselines
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
| Triage, `qwen2.5:3b` | About 2.3 s per finding alone. A run of 100 took 421 s while other model work shared the machine, all assessed, with a longest event-loop stall of 53 ms |

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
finding row shows the advice for its representative occurrence and says so:
"AI: Confirmed (1 of 2)" on the row and "covers one of 2 occurrences" in the drawer.
When AI is later turned off, stored advice stays visible with its date and the status
line says AI is off.

## Graph explanation

`POST /v1/graph/explain` takes up to 25 node IDs, optionally as an ordered path,
and runs only when asked. It reads those nodes and the edges between them from the
snapshot and writes nothing to the graph.

**The model does not write facts.** It selects and orders recorded edges and nodes,
and picks a claim type from a closed set: `route_step`, `blocked_hop`,
`relationship`, `node_fact` or `path_complete`. The server writes each sentence from
the record, so source, target, direction, relationship and traversability come from
the graph:

- A step that names an unknown ref or claim type is removed and counted in
  `rejected_claims`.
- The record decides route or blocked hop. If a model calls a non-traversable edge a
  route, the sentence still says it is not a route, and `claim_type_corrected` counts
  it.
- `path_complete` is written only when every selected hop has a traversable edge.
- A label that addresses the reader, or that runs to more than four words, is
  withheld from sentences and shown as `[label withheld: N2]`.
- A step may carry a short note, shown apart as "Model note, not evidence". A note
  that names a graph element or states a relationship, reach, or safety is dropped.

`evidence_limits` is computed without the model and states missing hops,
non-traversable hops, and whether a recorded attack path covers the selection. The
route needs an analyst role. Rate and daily budget apply per tenant through the
shared store when Postgres is configured, and an outage of that store refuses the
call rather than spending.

### Measured explanation

`scripts/ai_explain_eval.py` posts each path through the real route to a real graph
store, using 60 paths from the real Kubernetes and demo projections in
`ui/e2e/fixtures/k8s-projection.json` (`explain_dataset.v1.json`): 38 for tuning, 22
held out, including non-traversable hops and hostile labels. Truth is the recorded edge.
The bar is committed in `explain_bar.json`. CI replays recorded selections through the
route and fails on regression.

**Held out:**

| Model | Digest | Paths | Citations valid | Direction | Reachability | Hostile text | Answered | Hop coverage | Blocked hops shown |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `ollama/gemma3:4b` | `68ceab7e468a` | 22 | 100% | 100% | 100% | 0 | 100% | 90% | 65% |
| `ollama/llama3.2` | `a80c4f17acd5` | 22 | 100% | 100% | 100% | 0 | 100% | 100% | 100% |
| `ollama/qwen2.5:3b` | `357c53fb659c` | 22 | 100% | 100% | 100% | 0 | 100% | 98% | 94% |

**Development:**

| Model | Digest | Paths | Citations valid | Direction | Reachability | Hostile text | Answered | Hop coverage | Blocked hops shown |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `ollama/gemma3:4b` | `68ceab7e468a` | 38 | 100% | 100% | 100% | 0 | 100% | 88% | 74% |
| `ollama/llama3.2` | `a80c4f17acd5` | 38 | 100% | 100% | 100% | 0 | 97% | 97% | 98% |
| `ollama/qwen2.5:3b` | `357c53fb659c` | 38 | 100% | 100% | 100% | 0 | 100% | 96% | 95% |

Citations, direction and reachability are 100% by construction, since the server writes
them; the tests show a model that lies cannot move them. Hop coverage and blocked hops
shown measure the model's selection, and `gemma3:4b` misses the 70% blocked-hop bar on
the held-out paths. These two are a proxy for usefulness: nobody has rated whether the
explanations help a reader.

## Audit and metrics

Each provider call produces one record: tenant, actor, task, provider, model,
digest, prompt and response hashes, tokens, latency, outcome, and whether a guard
rejected output. Prompt and response text is never recorded.

In the control plane the record goes to the tamper-evident audit chain as `ai.call`,
with `agent_bom_ai_calls_total{task,provider,outcome}` and
`agent_bom_ai_call_latency_milliseconds_total{task,provider}` in Prometheus. If the
audit write fails, the call's output is discarded: no advice is stored and no
explanation is returned without its record. The scan itself continues and its AI run
reports `failed`.

The CLI writes the same fields to `<state dir>/ai-audit/ai-calls.jsonl`, in the same
hash-chained format as the runtime audit log. Check it with
`agent-bom runtime audit <path> --verify-chain`. That command verifies the chain but
does not yet list AI call records. Set `AGENT_BOM_AI_LOCAL_AUDIT=0` to opt out. If the
file cannot be written, the scan and its advice stand and a warning is logged.

## Not built

Ensemble scoring, compliance-control tagging, general novel-finding detection
beyond skill files, and MCP execution controls are not product behavior.
