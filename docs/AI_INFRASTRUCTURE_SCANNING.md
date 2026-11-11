# AI Infrastructure Scanning

agent-bom treats AI infrastructure dependencies as first-class supply chain components. GPU drivers, CUDA libraries, ROCm runtimes, and ML framework packages all carry CVEs that propagate through your AI stack.

## Why AI infrastructure matters

A vulnerability in `nvidia-cudnn-cu12` or `hip-python` doesn't just affect one model — it affects every inference pipeline running on that GPU fleet. agent-bom maps these dependencies into the same blast radius analysis used for MCP servers.

## Supported AI infrastructure packages

### NVIDIA CUDA ecosystem

| Package | Description |
|---------|-------------|
| `cuda-python` | CUDA Python bindings |
| `cupy`, `cupy-cuda11x`, `cupy-cuda12x` | NumPy-like GPU arrays |
| `nvidia-cublas-cu11/cu12` | CUDA BLAS library |
| `nvidia-cudnn-cu11/cu12` | CUDA Deep Neural Network library |
| `nvidia-cufft-cu11/cu12` | CUDA FFT library |
| `nvidia-cusolver-cu11/cu12` | CUDA solver library |
| `nvidia-cusparse-cu11/cu12` | CUDA sparse matrix library |
| `nvidia-nccl-cu11/cu12` | NVIDIA Collective Communications Library |
| `nvidia-cuda-runtime-cu11/cu12` | CUDA runtime |
| `nvidia-cuda-nvrtc-cu11/cu12` | CUDA NVRTC (runtime compilation) |
| `tensorrt`, `nvidia-tensorrt` | NVIDIA TensorRT inference optimizer |
| `triton`, `tritonclient` | NVIDIA Triton Inference Server |

### AMD ROCm ecosystem

| Package | Description |
|---------|-------------|
| `hip-python` | HIP Python bindings (AMD GPU) |
| `rocm-smi` | ROCm System Management Interface |
| `torch` (ROCm build) | PyTorch with ROCm backend |
| `tensorflow-rocm` | TensorFlow with ROCm backend |

### ML frameworks with GPU backends

| Package | Description |
|---------|-------------|
| `torch`, `torchvision`, `torchaudio` | PyTorch ecosystem |
| `tensorflow`, `tensorflow-gpu` | TensorFlow ecosystem |
| `jax`, `jaxlib` | Google JAX |
| `vllm` | vLLM inference engine |
| `text-generation-inference` | HuggingFace TGI |
| `llama-cpp-python` | llama.cpp Python bindings |

### MLOps & experiment tracking

| Package | Description |
|---------|-------------|
| `mlflow` | ML experiment tracking |
| `wandb` | Weights & Biases |
| `ray` | Distributed computing |
| `clearml` | ML pipeline management |

### AI observability and evaluation tracing

| Package | Description |
|---------|-------------|
| `langsmith` | LangSmith tracing and evaluation telemetry |
| `langfuse` | Langfuse traces, sessions, scores, and prompt telemetry |
| `braintrust` | Braintrust evaluation and experiment telemetry |
| `arize`, `arize-phoenix` | Arize/Phoenix observability and OpenInference traces |
| `trubrics` | Trubrics feedback and evaluation telemetry |
| `@helicone/helicone` | Helicone request and LLM observability instrumentation |

## Vendor advisory feed support

agent-bom separates structured vendor feeds from curated seed data so operators
can tell which advisory matches are feed-backed and which are best-effort
coverage. The source catalog is exposed through `GET /v1/intel/sources` and
the `intel_sources` MCP tool; the daily brief uses the same metadata when it
reports vendor advisory matches.

| Source | Status | Connector | Matching scope | Boundary |
|---|---|---|---|---|
| NVIDIA CSAF | supported | `csaf_json` | CUDA, cuDNN, NCCL, TensorRT, Triton, NIM, NeMo, PyTorch/vLLM mappings, and related GPU container/package signals | Structured CSAF records are matched and source-linked; year windows follow current and previous year feeds. |
| AMD PSIRT | experimental | `vendor_json_seed` | ROCm and AMD GPU package/image signals from curated advisory seeds | No open-ended website scraping is shipped; matches remain source-linked and marked experimental. |
| Intel PSIRT | experimental | `curated_seed` | GPU and oneAPI advisory seeds | No automated webpage scraping is shipped; matches remain source-linked and marked experimental. |

Daily threat briefs summarize local database evidence, submitted inventory, and
governed caller-supplied threat inputs. When a caller supplies IoC telemetry,
campaign activity, ransomware claims, and a tenant sector/geo profile, the brief
adds exact telemetry-hit matches and profile-overlap matches with source URL,
license/terms, fetched time, content hash, validation status, and match reason.
They still do not claim open-ended vendor webpage scraping; vendor pages remain
structured feed or curated source-linked seed coverage unless a governed
connector policy explicitly allows more.

## Scanning GPU container images

### NVIDIA CUDA images

```bash
# Scan official NVIDIA CUDA base image
agent-bom agents --image nvcr.io/nvidia/cuda:12.4.1-devel-ubuntu22.04

# Scan NVIDIA PyTorch NGC container
agent-bom agents --image nvcr.io/nvidia/pytorch:24.01-py3

# Scan NVIDIA Triton Inference Server
agent-bom agents --image nvcr.io/nvidia/tritonserver:24.01-py3
```

### AMD ROCm images

```bash
# Scan AMD ROCm PyTorch image
agent-bom agents --image rocm/pytorch:rocm6.0_ubuntu22.04_py3.10_pytorch_2.1.1

# Scan AMD ROCm base terminal
agent-bom agents --image rocm/rocm-terminal:latest

# Scan ROCm TensorFlow image
agent-bom agents --image rocm/tensorflow:rocm6.0-tf2.15
```

### Inference server images

```bash
# Scan vLLM GPU image
agent-bom agents --image vllm/vllm-openai:latest

# Scan HuggingFace TGI
agent-bom agents --image ghcr.io/huggingface/text-generation-inference:latest
```

Scanning an inference server image finds the packages in it. It does not show
that a server is running, which models it serves or who can call it.

## Model-serving endpoint evidence

Each kind of evidence is separate. Finding a package, image or model file does
not count as endpoint, configuration or effective-access coverage.

| Runtime | Package / image / file detection | Endpoint probe (read sent) | Runtime identity confirmed by | Model fields recorded |
|---|---|---|---|---|
| Ollama | `.gguf` model files; `~/.ollama` manifests | `--ollama` / `--ollama-host`: `GET /api/tags` | the `/api/tags` response shape | name:tag, digest; load state not reported |
| vLLM | `vllm` package and import; `vllm/vllm-openai` image | `--serving-endpoint vllm=URL`: `GET /v1/models`, `GET /version` | `owned_by: vllm` | served id, `root` artifact, runtime version |
| Text Generation Inference | `text-generation-inference` package; TGI image | `--serving-endpoint tgi=URL`: `GET /info` | `router` field | `model_id`, `model_sha` digest, runtime version |
| Triton | `tritonclient` package; `nvidia/tritonserver` image | `--serving-endpoint triton=URL`: `POST /v2/repository/index` with an empty body (a listing request), `GET /v2` | server metadata `name: triton` | model name, version, state such as `READY` / `UNAVAILABLE` |
| llama.cpp server | `llama-cpp-python` package; `.gguf` files | `--serving-endpoint llamacpp=URL`: `GET /v1/models`, `GET /props` | `owned_by: llamacpp` | served model path, `build_info` |
| LM Studio | None | `--serving-endpoint lmstudio=URL`: `GET /api/v0/models` | native fields such as `compatibility_type` | model id, `loaded` / `not-loaded` state |

Each endpoint probe has one of five outcomes:

| Outcome | Result |
|---|---|
| `success` | One record per listed model. |
| `partial` | Records that matched the documented shape are kept, with a partial warning. Records that did not match, or a failed metadata read, make it partial. |
| `denied` (401/403), `timeout`, `unavailable` (refused, other status, redirect, wrong API shape, unsafe URL) | No records, an incomplete warning, a `collector_failed` scan issue and exit code 1. Nothing is replaced with local files or another endpoint's inventory. |

Every model record carries `metadata.serving_evidence`. It keeps the runtime
(name, version, and whether the identity was confirmed or only declared), the
endpoint (URL, host, port), the model artifact (served name, artifact
reference, digest, version, state) and the collection (status, completeness,
observation time, reads sent) as separate fields. Container, GPU, calling
agent and principal are `null` because an endpoint listing cannot supply
them. Bind address, public reachability, TLS, authentication, model-load
policy, rate limits, quotas, logging and persistence are listed under
`not_collected`. A listener that answers is not proof of public reachability
or of missing authentication. Each `--serving-endpoint` value is probed
separately, so one failed endpoint is reported beside a successful one.
URLs with embedded credentials, a query or a fragment are refused, and
redirects are not followed. Bearer-token authentication to a protected
endpoint is not supported yet, so a protected endpoint reports `denied`.

The outcomes are qualified in `tests/cloud/test_serving_runtime_qualification.py`
and `tests/cloud/test_ollama_outcomes.py` against loopback fixtures that copy
each runtime's documented responses. No runtime is installed or started, and
no model is downloaded. This is not certification against a live provider.
The records reach JSON reports and the graph as agents. The API, MCP tools
and HTML reports do not yet show `serving_evidence` as its own view.

## GPU fleet scanning patterns

GPU node pools (EKS, GKE, AKS, Snowflake SPCS, Databricks), Kubernetes GPU
workloads and their identities, the node driver / Container Toolkit, GPU
posture checks and model files inside images are covered in
[GPU and AI infrastructure coverage](../site-docs/features/gpu-ai-infrastructure.md),
including what is not covered.

### Kubernetes GPU operator

```bash
# Scan NVIDIA GPU Operator components
agent-bom agents --image nvcr.io/nvidia/gpu-operator:v24.3.0
agent-bom agents --image nvcr.io/nvidia/k8s-device-plugin:v0.15.0
agent-bom agents --image nvcr.io/nvidia/dcgm-exporter:3.3.5-3.4.1-ubuntu22.04

# Scan all GPU pods in a namespace
agent-bom agents --k8s --namespace gpu-workloads -f json -o gpu-fleet-scan.json
```

### Multi-cloud GPU fleet

```bash
# CoreWeave GPU instances
agent-bom agents --image <your-gpu-workload-image> --enrich -f json

# Lambda Labs GPU cloud
agent-bom agents --image <lambda-workload-image> --enrich -f json

# Nebius AI cloud
agent-bom agents --nebius -f json -o nebius-ai-scan.json
```

## Credential boundaries

Prefer read-only credentials. A scan sees only the cloud account, project,
workspace, namespace, registry, or local endpoint that the provided credential
can inspect. Treat that boundary as part of the evidence.

| Surface | First command | Credential boundary | Data read | Artifact |
|---|---|---|---|---|
| AWS AI and GPU infrastructure | `agent-bom agents --preset enterprise --aws` | AWS profile, role, or web identity scoped to read-only inventory | account, region, EKS/ECS/Lambda/IAM/S3 and AI-service metadata visible to the role | JSON/HTML findings, graph-ready cloud inventory, optional CIS evidence |
| Azure AI surfaces | `agent-bom agents --preset enterprise --azure` | Azure identity or service principal scoped to selected subscriptions/resource groups | Azure AI, container, identity, and resource metadata visible to the principal | JSON/HTML findings and cloud inventory |
| GCP Vertex AI and cloud resources | `agent-bom agents --preset enterprise --gcp` | ADC or service account scoped to selected projects | Vertex AI, IAM, storage, compute, and project metadata visible to the service account | JSON/HTML findings and cloud inventory |
| Snowflake AI Data Cloud | `agent-bom agents --preset enterprise --snowflake` | Snowflake role/user scoped by warehouse, database, schema, and account grants | Cortex, warehouse, role, object, task, stream, and query metadata visible to the role | Snowflake posture evidence and compliance-ready inventory |
| Databricks workspaces | `agent-bom agents --preset enterprise --databricks` | Databricks host/token or configured workspace identity | workspace, cluster/job, model, secret-scope names, and notebook metadata visible to the token | workspace inventory and findings |
| Hugging Face model and registry evidence | `agent-bom agents -p . --enrich` or provider-specific scan path | public Hub access or optional token for private model metadata | model card, repository, file, license, and provenance metadata visible to the caller | model provenance and supply-chain evidence |
| OpenAI and hosted model providers | `agent-bom agents -p .` plus provider inventory where configured | repo-local code/config and any configured read-only provider inventory token | SDK imports, model names, endpoint references, and provider-visible metadata where supported | AI inventory, provider references, and graph-ready model/service nodes |
| W&B, MLflow, and observability tools | `agent-bom agents -p .` plus configured provider scan | workspace/project token scoped by the provider | experiment, run, model registry, and trace metadata visible to the token | MLOps inventory and related findings |
| Ollama and local model runtimes | `agent-bom agents --preset enterprise --ollama` | local endpoint access on the inspected host or network boundary | local model/runtime metadata exposed by the endpoint | local model runtime inventory |

Scan artifacts should record credential environment variable names, role names,
workspace identifiers, and source paths where needed for investigation; they
should not store provider secret values.

## CI/CD integration

### GitHub Actions — GPU image gate

```yaml
- uses: koda-ai-studio/agent-bom@v0
  with:
    scan-type: image
    image: nvcr.io/nvidia/cuda:12.4.1-devel-ubuntu22.04
    fail-on-severity: high
    format: sarif
    output-file: gpu-scan.sarif

- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: gpu-scan.sarif
```

### Policy enforcement

```yaml
# policy.yml — block critical GPU library vulnerabilities
rules:
  - name: block-critical-gpu-vulns
    condition:
      severity: critical
      package_pattern: "nvidia-*|cuda-*|rocm-*|hip-*"
    action: fail
    message: "Critical GPU infrastructure vulnerability — blocks deployment"
```

## Example scan scripts

See [`examples/ai-infra/`](../examples/ai-infra/) for ready-to-run scan scripts:

- `nvidia-cuda-scan.sh` — Scan NVIDIA CUDA + NGC images
- `amd-rocm-scan.sh` — Scan AMD ROCm images
- `pytorch-triton-scan.sh` — Scan PyTorch + Triton inference
- `gpu-fleet-k8s-scan.sh` — Scan Kubernetes GPU workloads


### Argument-flow evidence in JSON

Scan a Python project with `agent-bom scan -p ./project -f json -o report.json`.
In a blast-radius row, `symbol_reachability_tainted_argument` is `true` when
bounded local analysis traces any call argument to a function parameter or a
recognized untrusted source. Straight-line local assignments are followed;
reassignment replaces the prior value. `false` means the supported analysis
found no such flow. `null` means analysis is unavailable, including advisories
without affected symbols, unsupported languages or control flow, and unknown
external values. Inspect the affected symbols and call evidence before deciding
whether the vulnerable parameter can receive attacker-controlled input. This
field does not prove exploitability or change severity or reachability verdicts.
