# Kubernetes Deployment

> **You do not need to read this unless** you are working with the raw
> `deploy/k8s/` manifests, the optional sidecar-injection webhook, or
> low-level Helm value tuning. The paved EKS rollout paths are
> [Vanilla EKS Quickstart](eks-vanilla-quickstart.md) and
> [Your Own AWS / EKS](own-infra-eks.md); the chart contract lives in
> [Packaged API + UI Control Plane](control-plane-helm.md).

## Pre-built manifests

Located in `deploy/k8s/`:

| Manifest | Purpose |
|----------|---------|
| `namespace.yaml` | `agent-bom` namespace |
| `rbac.yaml` | ServiceAccount + read-only ClusterRole (get/list on workloads, pods, service accounts, RBAC, NetworkPolicies, nodes and admission objects; never Secrets) |
| `cronjob.yaml` | Scheduled scan every 6 hours |
| `daemonset.yaml` | Optional node-wide runtime monitor |
| `sidecar-example.yaml` | Proxy sidecar alongside an MCP server |
| `proxy-sidecar-pilot.yaml` | Focused EKS pilot sidecar pattern for selected MCP workloads |

Those static manifests are still the scanner/runtime path.

The packaged Helm chart now also ships an optional mutating webhook for the
HTTP/SSE sidecar path:

- enable `sidecarInjection.enabled=true`
- opt in an entire namespace with label `agent-bom.io/proxy-inject=enabled`
- or opt in a single workload with pod label `agent-bom.io/proxy=true`
- declare the local MCP target with annotation `agent-bom.io/mcp-url` or
  `agent-bom.io/mcp-port`

If you want the packaged API + dashboard control plane, use the Helm chart
described below.

## Runtime boundary

`agent-bom` now has two distinct Kubernetes security surfaces:

- manifest hardening
  - `agent-bom iac k8s/`
  - scans YAML/Helm content in Git or on disk
- point-in-time cluster posture
  - `agent-bom iac . --k8s-live --k8s-all-namespaces`
  - inspects runtime state through `kubectl` or the in-cluster API
  - covers pod security and health, RBAC drift, namespace NetworkPolicy
    coverage, admission control (below) and, opt-in, kubelet `configz`
- workload inventory and graph
  - `agent-bom scan --k8s --namespace <ns>` (or `-A`) for a live cluster
  - `agent-bom scan --iac <dir>` for manifests and Helm charts
  - see [Workload graph](#workload-graph)

The runtime path is intentionally scoped. It does not claim event-driven
Kubernetes monitoring, service-mesh analysis, policy-engine rule evaluation, or
arbitrary controller-state analysis.

## Workload graph

Live clusters and manifests produce the same model, recorded in the scan
report's `kubernetes_inventory` section and projected into the graph:

```text
cluster ─contains→ namespace ─contains→ workload ─depends_on→ image ─contains→ package ─vulnerable_to→ CVE
                                          │
                                          ├─assumes→ service account ─inherits→ Role / ClusterRole
                                          │                 ├─has_permission→ namespace or cluster (binding scope)
                                          │                 └─can_access→ Secret (by name)
                                          └─can_access→ Secret it mounts or references
```

- **Workloads**: Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob
  and Pod. Live pods collapse into the controller that owns them
  (Pod → ReplicaSet → Deployment, Pod → Job → CronJob) when that controller was
  read; a pod whose owner was not read stays its own workload.
- **Images**: keyed by registry digest when the source recorded one. Live
  scans read the running digest from each pod's container status and scan the
  image at that digest (`repo@sha256:…`), so the CVEs are for what actually
  runs. Manifests key images by the reference as written unless it pins a digest.
  Image scans (`--image`, `--k8s`, the `scan` MCP tool and API scans) project
  as image nodes, not as agents or MCP servers.
- **Service accounts**: the pod's `serviceAccountName` (or `default`), with
  whether a token is mounted (pod setting, then the service account's
  `automountServiceAccountToken`, and any projected `serviceAccountToken`
  volume). A workload without a mounted token keeps its `assumes` edge but it is
  not traversable.
- **RBAC**: one grant per RoleBinding / ClusterRoleBinding subject that is a
  ServiceAccount, scoped to the binding's namespace or the cluster. Secret
  access is resolved from the rules (`get`/`list`/`watch` on `secrets`,
  honouring `resourceNames`). A binding whose role was not read is recorded as
  unresolved; only the default `cluster-admin`, `admin`, `edit` and `view`
  ClusterRoles are filled in from their upstream definitions.
- **Secrets**: named only. No collector ever lists Secrets; the transport
  allowlist refuses them, so no secret value can enter a report.
- **MCP servers in pods** (`--k8s-mcp`) are hosted on their pod, and the pod
  on its node VM; when `--k8s` reads the same namespace in that scan, the server
  is also hosted on the pod's workload. On AWS, Azure and GCE the node VM
  is the same graph node cloud inventory and disk side-scan produce, so an OS
  CVE on the node disk is an attack path through the pod.

Attack paths:

- **CVE → workload**: `cluster → namespace → workload → image → package → CVE`
  (and `agent → MCP server → workload → …` for MCP servers running in pods).
- **Workload → identity pivot**: for every workload holding an applicable CVE,
  `workload → service account [→ role] → secret / namespace / cluster`, with the
  CVEs that make the workload the foothold on the path. A workload with no
  mounted token never starts one.

Surfaces: CLI console (most-vulnerable-first workload table) and `-f json`
(`kubernetes_inventory`, with each container's image scan result), API scans
(`k8s: true`, and repository scans for manifests), the API graph and
attack-path endpoints, and the `kspm_workload_inventory` MCP tool.

Limits:

- Point-in-time reads; no watch/informer stream.
- User and Group RBAC subjects are counted, not modelled.
- Aggregated ClusterRoles are resolved only through the rules the API returns
  for them; custom roles that were not readable stay unresolved.
- Manifest and Helm inventories have no cluster name and no running digests;
  their image CVEs appear only when the same image reference is also scanned.
- Helm charts are rendered with default values via `helm template`; a chart
  that cannot be rendered is reported, and its workloads are not in the
  inventory.
- A forbidden or failed read is recorded per collector (`unevaluable` /
  `failed`) and makes the inventory `partial`; unreadable pods fail it.

## Admission control

Read-only checks over objects listed from
`admissionregistration.k8s.io/v1` and namespace labels:

| Rule | Severity | Check | Mapping |
|------|----------|-------|---------|
| `K8S-ADM-001` | medium | Namespace running workloads has no `pod-security.kubernetes.io/enforce` label | CIS Kubernetes 5.2.1 |
| `K8S-ADM-002` | medium | Namespace enforces the `privileged` Pod Security level | CIS Kubernetes 5.2.1 |
| `K8S-ADM-004` | high | No namespace enforces `baseline`/`restricted`, no ValidatingAdmissionPolicy binding denies, and no validating webhook exists | CIS Kubernetes 5.2.1 |
| `K8S-ADM-005` | low | ValidatingAdmissionPolicyBinding only warns or audits (no `Deny`) | — |
| `K8S-ADM-006` | medium | ValidatingAdmissionPolicy has `failurePolicy: Ignore` | — |
| `K8S-ADM-007` | medium | Validating webhook has `failurePolicy: Ignore` | — |
| `K8S-037` / `K8S-038` | medium | Namespace manifest without an enforce level / enforcing `privileged` | CIS Kubernetes 5.2.1 |

`kube-system`, `kube-public` and `kube-node-lease` are exempt from the namespace
checks. `K8S-ADM-004` is raised only when namespaces, ValidatingAdmissionPolicies,
their bindings and validating webhooks were all readable; on clusters older than
Kubernetes 1.30 (no `admissionregistration.k8s.io/v1` ValidatingAdmissionPolicy)
that collector is `unevaluable` and the cluster-wide check is not made. What a
policy engine's webhook actually enforces is not evaluated.

## Quick start

```bash
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/rbac.yaml
kubectl apply -f deploy/k8s/cronjob.yaml

# Inspect live cluster posture through kubectl
agent-bom iac . --k8s-live --k8s-all-namespaces
```

## Helm chart

```bash
# Install with defaults
helm install agent-bom deploy/helm/agent-bom/ \
  -n agent-bom --create-namespace

# Enable the optional node-wide runtime monitor
helm install agent-bom deploy/helm/agent-bom/ \
  -n agent-bom --create-namespace \
  --set monitor.enabled=true

# Package the API + UI control plane
helm install agent-bom deploy/helm/agent-bom/ \
  -n agent-bom --create-namespace \
  --set controlPlane.enabled=true \
  --set controlPlane.ingress.enabled=true

# Custom schedule
helm install agent-bom deploy/helm/agent-bom/ \
  -n agent-bom --create-namespace \
  --set scanner.schedule="0 */2 * * *"
```

### Key values

| Value | Default | Description |
|-------|---------|-------------|
| `scanner.enabled` | `true` | Deploy CronJob scanner |
| `scanner.schedule` | `0 */6 * * *` | Cron schedule |
| `scanner.allNamespaces` | `true` | Scan all namespaces |
| `scanner.extraArgs` | `[]` | Add scan flags like `--k8s-mcp`, `--enforce`, or `--introspect` |
| `scanner.env` | `[]` | Extra environment variables for the scanner CronJob |
| `monitor.enabled` | `false` | Deploy the optional node-wide monitor DaemonSet |
| `monitor.port` | `8423` | HTTP port for protect endpoint |
| `monitor.serviceAccount.create` | `true` | Create a dedicated monitor service account instead of reusing the shared chart identity |
| `controlPlane.enabled` | `false` | Package API + dashboard Deployments and Services |
| `controlPlane.ingress.enabled` | `false` | Add same-origin ingress routing for UI + API |
| `controlPlane.ui.env` | `NEXT_PUBLIC_API_URL=\"\"` | Blank by default so the browser uses same-origin paths |
| `sidecarInjection.enabled` | `false` | Package the cert-manager-backed mutating webhook for proxy sidecar auto-injection |
| `networkPolicy.restrictIngress` | `true` | Deny ingress by default; add explicit ingress policy rules for allowed callers |
| `rbac.create` | `true` | Create RBAC resources |
| `serviceAccount.annotations` | `{}` | Attach provider-specific identity such as AWS IRSA |

For the full control-plane topology and secret wiring, see
[Packaged API + UI Control Plane](control-plane-helm.md).

Use the monitor only when you explicitly want node-wide runtime coverage. The
default secure path remains:

- agentless scans
- fleet sync
- gateway for shared remote MCPs
- selected sidecar proxies where inline enforcement matters

For the narrower MCP and agents pilot, see
[Focused EKS MCP Pilot](eks-mcp-pilot.md).

For employee laptops and workstations that should sync into the same control
plane, see [Endpoint Fleet](endpoint-fleet.md).
