# GPU and AI Infrastructure Coverage

agent-bom inventories GPU capacity read-only, connects it to the workloads that
run on it and the identities they hold, matches the host GPU stack against
advisories, and reports GPU posture. This page says what is read, what the
graph contains, which checks run, and where the coverage stops.

## What is read, per provider

Every read is a list/describe/get call or a `SHOW` statement. Nothing is
written to a cloud account, cluster or warehouse, and nothing runs inside a
pod.

| Source | Calls | GPU facts kept |
|---|---|---|
| AWS EKS | `eks:ListClusters`, `eks:DescribeCluster`, `eks:ListNodegroups`, `eks:DescribeNodegroup` | per managed node group: instance types, GPU model and count per node (EC2 P/G/Inf/Trn families), AMI type, min/max/desired size, node IAM role, labels, taints, SSH remote-access exposure |
| AWS EC2 | `ec2:DescribeInstances` (existing inventory) | GPU model and count for accelerated instance types |
| GCP GKE | `container.clusters.list` | per node pool: accelerators (type, count), GPU sharing (time-sharing / MPS, clients per GPU), MIG partition size, GPU driver install setting (`DEFAULT`, `LATEST`, `INSTALLATION_DISABLED`), node service account, autoscaling bounds, taints |
| GCP GCE | `compute.instances.list` (existing inventory) | attached `guestAccelerators`; A2/A3/A4/G2 machine types carry their bundled GPUs |
| Azure AKS | `Microsoft.ContainerService/managedClusters/read` | per agent pool: GPU VM size (N-series), MIG instance profile, `gpuProfile.driver` opt-out, node public IPs, taints, autoscaling bounds |
| Azure VMs | existing VM inventory | GPU model for N-series sizes |
| Snowflake SPCS | `SHOW COMPUTE POOLS` (needs MONITOR, USAGE or OWNERSHIP on a pool to see it) | instance family, GPU model and count for `GPU_*` families, node bounds, services, owner, exclusivity |
| Databricks | `clusters/list`, `clusters/list-node-types` | worker and driver node types, GPU count reported by the workspace, ML GPU runtime, access mode |
| Kubernetes (`--gpu-scan`) | `kubectl get nodes`, `kubectl get pods --all-namespaces`, `kubectl get clusterpolicies.nvidia.com`, `kubectl config view --minify` | GPU pods (any `nvidia.com/gpu`, `nvidia.com/mig-*`, `amd.com/gpu`, `gpu.intel.com/*` request or limit), their node pool, service account, IRSA role (`AWS_ROLE_ARN`), privileged / hostPath / host-namespace settings, names of secret-sourced env vars (never values), node driver version from GPU Feature Discovery labels, Container Toolkit and driver versions declared by the GPU Operator `ClusterPolicy` |

GPU pools are recorded on their cluster in the cloud inventory payload
(`node_pools` on each `eks_clusters`, `gke_clusters` and `container_clusters`
entry; non-GPU pools are kept with `gpu: false`). The connection inventory
summary reports `node_summary.gpu_node_pools`.

## Graph model

| Node / edge | Meaning |
|---|---|
| `cloud_resource` with `resource_type=gpu_node_pool` | an EKS node group, GKE node pool, AKS agent pool, or a Kubernetes pool seen only through node labels |
| cluster `contains` pool | the pool belongs to the inventoried cluster |
| pool `assumes` role / service account | the pool's node IAM role (EKS) or node service account (GKE), when that identity is in the graph |
| GPU workload agent `hosted_on` pool | the pod is scheduled on (or selects) that pool |
| GPU workload agent `authenticates_as` Kubernetes service account `assumes` IAM role | the pod's service account and the IRSA role the EKS pod-identity webhook injected |
| workload server `depends_on` `nvidia-gpu-display-driver` / `nvidia-container-toolkit` | the node GPU stack, with NVD CPE identity, matched like any package (NVD CPE ranges, NVIDIA CSAF, KEV enrichment) |
| `cloud_resource` with `resource_type=compute_pool` | a Snowflake SPCS compute pool, contained by its account, with `gpu` set for GPU families |

The pool node id is derived from the provider cluster key, so a pool read from
the EKS/GKE API and the same pool seen through `kubectl` land on one node:
EKS kubeconfig contexts named after the cluster ARN and GKE contexts named
`gke_<project>_<location>_<cluster>` are recognised. Any other context (AKS
contexts carry only the cluster name) stays keyed by the context name, so it is
never merged with an unrelated cluster.

**Attack paths.** When the driver or Container Toolkit on a GPU workload's node
matches a CVE, the served attack paths include the workload's service account
and IRSA role, and the GPU node pool with its node identity. These paths keep
`reachability: unknown`: the topology is recorded, exploitation is not.

## Posture checks

All checks are read-only and provider-aware: a check runs only where the
provider exposes the setting and its default makes the condition meaningful.
Findings go through the unified findings stream (CLI, JSON, SARIF, API, MCP)
with `evidence.category = gpu_posture` and attach to the pool or workload
node in the graph.

| Check | Providers | Severity | Condition |
|---|---|---|---|
| GPU-001 | AWS | high | EKS node group sets an SSH key without source security groups (port 22 open to 0.0.0.0/0) |
| GPU-002 | Azure | medium | AKS GPU agent pool assigns public IPs to nodes |
| GPU-003 | GCP | medium | GKE GPU node pool runs as the Compute Engine default service account |
| GPU-004 | AWS, Azure | low | GPU pool has no NoSchedule/NoExecute taint. Not run on GKE: GKE adds `nvidia.com/gpu=present:NoSchedule` to GPU nodes itself when the cluster has a non-GPU pool, so a node-pool config without the taint is not evidence |
| GPU-005 | AWS, GCP, Azure | low | the NVIDIA driver is operator-managed (EKS `CUSTOM` or non-accelerated AMI on GPU hardware, GKE `INSTALLATION_DISABLED`, AKS `gpuProfile.driver=None`) |
| GPU-006 | GCP | low | the pool shares each GPU between containers (time-sharing or MPS) |
| GPU-010 | Kubernetes | high | a GPU pod runs a privileged container |
| GPU-011 | Kubernetes | high | a GPU pod mounts `/dev`, `/dev/nvidia*`, the device-plugin or pod-resources socket directory, `/run/nvidia`, a container runtime socket, or `/` from the host |
| GPU-012 | Kubernetes | medium | a GPU pod sets `hostPID`, `hostIPC` or `hostNetwork` |
| GPU-013 | Kubernetes | low | pods from two or more namespaces run on the same time-sliced or MPS pool (no GPU memory isolation between tenants) |
| GPU-020 | Databricks | medium | a GPU cluster uses the No Isolation Shared access mode |
| GPU-021 | Snowflake | low | a GPU compute pool runs more than one service and is not exclusive |

Outdated drivers and Container Toolkit releases are not judged by a separate
version list: the detected versions are packages, and their CVEs (for example
CVE-2024-0132 in Container Toolkit before 1.16.2) come from the same advisory
matching, KEV enrichment and severity gates as every other package.

## Model files in container images

`--image`, `--image-tar`, the API scan and the MCP `scan` tool record model
files found in image layers (`.pkl`, `.pt`, `.pth`, `.ckpt`, `.joblib`, `.bin`,
`.safetensors`, `.onnx`, `.gguf`, `.h5`, `.keras`, `.pb`, `.tflite`,
`.mlmodel`) in the image agent's `metadata.model_artifacts`, with layer
provenance. Pickle-bearing files are copied to a private temporary file and
their opcodes are disassembled; nothing is deserialized. Findings
(`MALICIOUS_MODEL`, `MODEL_INTEGRITY`) attach to the image in the findings
stream and the graph.

## Limits

- Driver and Container Toolkit versions are known only where something
  publishes them: GPU Feature Discovery node labels (driver) and the GPU
  Operator `ClusterPolicy` (driver and toolkit, as declared, not as observed on
  the node). EKS accelerated AMIs, GKE-installed drivers and AKS-installed
  drivers do not expose a version through the cloud API, so a cloud-only scan
  reports the pool's driver management mode, not a version or its CVEs.
- `kubectl` scope is the current (or `--gpu-k8s-context`) context and what its
  credentials can list; without cluster-wide `get pods`, workloads are not
  inventoried and the scan says so. AKS kube contexts cannot be tied to the
  ARM cluster id, so AKS workloads attach to a context-keyed pool node.
- Env vars sourced through `envFrom` are not expanded; only `env` entries are
  named. `AWS_ROLE_ARN` is the only env value kept.
- GPU counts per node come from provider tables for common sizes; an
  unlisted size keeps its GPU model with an unknown count rather than a guess.
  Databricks counts come from the workspace's node-type listing.
- TPUs, Trainium/Inferentia device plugins (`aws.amazon.com/neuron`) and
  Karpenter-provisioned nodes without a provider pool label are not modelled
  as GPU pools; Neuron instance families are classified as `aws-neuron`
  accelerators on node groups.
- Image model scanning applies the pickle byte cap (`AGENT_BOM_PICKLE_MAX_BYTES`,
  256 MiB by default): a larger pickle-bearing member is reported
  `OVERSIZE_PICKLE_UNSCANNED`, never as clean. At most 256 model files are
  recorded per image (`model_artifacts_capped` says when the cap was hit).
  Layer size, member and decompression limits are the OCI parser's own. Files
  are found by extension inside images; the filesystem scan's header-sniffing
  of renamed pickles does not run on image layers.
- The Docker-daemon fallback of `--image` (`docker export` when the saved
  image yields no packages) reads a flattened filesystem, not layers, and does
  not record model files.
