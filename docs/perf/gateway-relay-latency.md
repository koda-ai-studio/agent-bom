# Gateway Relay Latency Evidence

Evidence status: historical measurement (2026-07-23)
Related decision: [ADR-009](../decisions/009-python-primary-go-sidecar-later.md)
Raw result artifacts:

- [`results/gateway-relay-baseline-2026-07-23.json`](results/gateway-relay-baseline-2026-07-23.json)
- [`results/gateway-relay-tuned-2026-07-23.json`](results/gateway-relay-tuned-2026-07-23.json)
- [`results/gateway-relay-go-gate-2026-07-23.json`](results/gateway-relay-go-gate-2026-07-23.json)
- [`results/gateway-relay-go-spike-2026-07-23.json`](results/gateway-relay-go-spike-2026-07-23.json)
- [`results/gateway-relay-decision-2026-07-23.json`](results/gateway-relay-decision-2026-07-23.json)
- [`results/gateway-relay-go-spike-2026-07-24.json`](results/gateway-relay-go-spike-2026-07-24.json)

## Claim

Local full-stack `agent-bom gateway serve` JSON-RPC relay latency and process RSS
were measured against a loopback mock MCP upstream across a concurrency ladder
up to 500 in-flight client requests. This page supports the Go-workload
isolation gate (ADR-009): whether Python remains adequate for the HTTP gateway
relay hot path, or whether Phase 2 contract extraction for an optional Go
sidecar is justified.

This page does **not** claim Helm/EKS multi-replica gateway latency, policy /
DLP / visual-leak paths, or stdio proxy performance.

## Scope

- Historical harness: [`scripts/run_gateway_relay_benchmark.py` at the measurement commit](https://github.com/koda-ai-studio/agent-bom/blob/52152995e/scripts/run_gateway_relay_benchmark.py); removed when the Go runtime tier was retired in #4474.
- Mock upstream: `scripts/perf/mock_mcp_upstream.py` (`POST /mcp` JSON-RPC echo)
- Gateway: `agent-bom gateway serve --bind 127.0.0.1:<port> --upstreams <tmp.yaml>`
- Client path: `POST /mcp/echo` with `tools/call`
- Modes:
  - **baseline** — default asyncio event loop; default httpx client limits
  - **tuned** — uvloop when installable; larger httpx client connection /
    keepalive limits on the load generator

## Go-gate SLO

At concurrency **500** (200 requests per level in this run), the gate trips if
**any** of the following hold on baseline **or** tuned:

| Metric | Threshold |
|--------|-----------|
| `p95_ms` | `> 50` |
| `peak_rss_mb` | `> 512` |
| `error_rate` | `> 0.01` (1%) |

**gate_tripped: true** (see decision artifact). Next step: `proceed_phase2`
(Python relay interface + contract tests; no Go sidecar in this PR).

## Environment

- Platform: macOS-26.5.2-arm64-arm-64bit-Mach-O
- Host: local-benchmark-host
- Python: 3.13.5
- agent-bom: 0.97.5 (worktree at `origin/main` / `v0.97.5`)
- Upstream: loopback FastAPI echo MCP (operator YAML → private-network approved)
- Gateway fail mode for this microbenchmark: `AGENT_BOM_GATEWAY_FAIL_MODE=open`
  (policy engine not under test)
- Tuned uvloop: enabled (`uvloop` present in the api extra / venv)
- Gateway upstream pool: `GatewaySettings.upstream_http_max_connections=100`
  / keepalive `20` — was **not** env-configurable at measurement time; tuned mode could not enlarge
  the gateway pool without a CLI/settings change

## Historical commands

These commands record the original measurement procedure at commit
`52152995e`; the retired harness is not available on current main. The
retained JSON artifacts above preserve the measurements. See ADR-009 for the
retirement decision; these results do not establish current-release latency.

```bash
uv run python scripts/run_gateway_relay_benchmark.py \
  --mode baseline \
  --output docs/perf/results/gateway-relay-baseline-2026-07-23.json

uv run python scripts/run_gateway_relay_benchmark.py \
  --mode tuned \
  --output docs/perf/results/gateway-relay-tuned-2026-07-23.json
```

## Results (excerpt)

Requests per concurrency level: **200**. Warmup: 20.

### Baseline

| Concurrency | p50 (ms) | p95 (ms) | p99 (ms) | error_rate | peak_rss_mb |
|---:|---:|---:|---:|---:|---:|
| 1 | 2.183 | 2.432 | 3.676 | 0.0 | 106.656 |
| 10 | 105.438 | 145.799 | 151.805 | 0.0 | 107.016 |
| 50 | 434.488 | 1632.071 | 2081.149 | 0.0 | 107.516 |
| 100 | 944.923 | 2534.814 | 2721.605 | 0.0 | 107.531 |
| 250 | 1384.837 | 2594.884 | 2674.59 | 0.0 | 107.656 |
| 500 | 1360.29 | **2547.357** | 2647.461 | 0.0 | 107.656 |

### Tuned (uvloop + larger client httpx limits)

| Concurrency | p50 (ms) | p95 (ms) | p99 (ms) | error_rate | peak_rss_mb |
|---:|---:|---:|---:|---:|---:|
| 1 | 2.142 | 2.553 | 3.471 | 0.0 | 106.141 |
| 10 | 103.556 | 235.799 | 302.326 | 0.0 | 106.672 |
| 50 | 507.455 | 1409.049 | 2185.622 | 0.0 | 107.031 |
| 100 | 879.809 | 2515.841 | 2669.775 | 0.0 | 107.047 |
| 250 | 1370.296 | 2572.973 | 2701.919 | 0.0 | 107.078 |
| 500 | 1378.941 | **2572.27** | 2669.068 | 0.0 | 107.078 |

### Gate inputs at concurrency=500

| Mode | p95_ms | peak_rss_mb | error_rate | Trips? |
|------|-------:|------------:|-----------:|--------|
| baseline | 2547.357 | 107.656 | 0.0 | yes (p95) |
| tuned | 2572.27 | 107.078 | 0.0 | yes (p95) |

RSS stays well under 512 MiB; errors stay at 0%. Latency under fan-in is the
failing dimension. Client-side uvloop / httpx keepalive did not close the gap
to the 50 ms p95 SLO (expected: bottleneck is gateway relay + default upstream
pool, not the load generator).

## Gaps

- Upstream pool/timeout/circuit settings are configurable (below), but these
  historical samples have not been rerun with the new operator controls.
- Single-process loopback only — no multi-replica Helm gateway, TLS, or auth.
- Empty / fail-open policy path only — no enforce-mode policy, DLP, firewall,
  or visual-leak cost in the samples.
- Mock upstream is an in-process FastAPI echo; real SaaS MCP RTT is excluded.
- EKS lab soak deferred to Phase 3/4 if a Go sidecar spike lands.

## Next

`gate_tripped=true` → proceed to Phase 2 (Python-only relay interface +
contract tests). Do not implement a Go sidecar until that contract exists
(ADR-009). Phase 2 Python extract: [`docs/design/GATEWAY_RELAY_CONTRACT.md`](../design/GATEWAY_RELAY_CONTRACT.md).

## Configure upstream limits

Start with an upstreams YAML and bind locally for a first-run check:

```bash
agent-bom gateway serve --upstreams upstreams.yaml --bind 127.0.0.1:8090 \
  --upstream-http-max-connections 100 \
  --upstream-http-max-keepalive-connections 20 \
  --upstream-http-timeout-seconds 30 \
  --upstream-failure-threshold 3 \
  --upstream-circuit-cooldown-seconds 30
```

The gateway exposes the configured upstreams on its MCP endpoint. Connect a
client and verify a permitted tool call before increasing concurrency. Preserve
incoming authentication and agent identity enforcement for non-loopback deploys.
These controls do not alter policy, authentication, or tenant isolation.

Each flag has an environment equivalent, shown by `gateway serve --help`:

| Flag | Environment variable | Default |
|---|---|---:|
| `--upstream-http-max-connections` | `AGENT_BOM_GATEWAY_UPSTREAM_HTTP_MAX_CONNECTIONS` | 100 |
| `--upstream-http-max-keepalive-connections` | `AGENT_BOM_GATEWAY_UPSTREAM_HTTP_MAX_KEEPALIVE_CONNECTIONS` | 20 |
| `--upstream-http-timeout-seconds` | `AGENT_BOM_GATEWAY_UPSTREAM_HTTP_TIMEOUT_SECONDS` | 30 |
| `--upstream-failure-threshold` | `AGENT_BOM_GATEWAY_UPSTREAM_FAILURE_THRESHOLD` | 3 |
| `--upstream-circuit-cooldown-seconds` | `AGENT_BOM_GATEWAY_UPSTREAM_CIRCUIT_COOLDOWN_SECONDS` | 30 |

CLI flags override environment values. The existing runtime validator rejects
invalid settings before control-plane discovery or listener startup: total
connections and failure threshold must be positive integers; keepalive must be
an integer from zero through the total pool; timeout must be finite and at least
0.001 seconds; cooldown must be finite and non-negative. Invalid settings fail
closed at startup. An open circuit continues to deny upstream calls until its
configured retry window. Benchmark with representative upstream latency and
policy enforcement before increasing pools; larger limits do not prove higher
throughput or a latency SLO.

The same environment variables work in Docker (`--env`) and Helm
(`gateway.env`). For example, in an existing gateway values file:

```yaml
gateway:
  env:
    - name: AGENT_BOM_GATEWAY_UPSTREAM_HTTP_MAX_CONNECTIONS
      value: "100"
    - name: AGENT_BOM_GATEWAY_UPSTREAM_HTTP_MAX_KEEPALIVE_CONNECTIONS
      value: "20"
    - name: AGENT_BOM_GATEWAY_UPSTREAM_HTTP_TIMEOUT_SECONDS
      value: "30"
```

Render the chart with `helm template agent-bom deploy/helm/agent-bom -f values.yaml`
before deploying, then check `/healthz` for the effective pool and circuit settings.
These controls do not enable multi-replica gateway persistence; the chart retains
its existing replica and durable-audit restrictions.
