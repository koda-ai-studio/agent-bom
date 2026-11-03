# Exceptions and policy for IaC

Platform and AppSec teams need two things from an IaC gate: block risky
changes, and let a specific, explained, by-design case through without
switching the rule off for everyone. agent-bom has one exception model for IaC
findings, whichever way the exception is declared, and a policy file that can
allow, warn or block by rule, resource and environment.

Every accepted exception:

- needs a **reason**;
- records **where it was declared** (`source` and `origin`), and optionally an
  **owner** and an **expiry**;
- leaves the active findings and every gate (`--fail-on-severity`, policy
  `block`), but **stays in the output**: the JSON `iac_findings.suppressed`
  list, SARIF `suppressions` (shown as dismissed in code-scanning UIs), the HTML
  report and the console summary (`N accepted exception(s)`);
- **stops applying the day after it expires**: the finding is active again and
  the scan prints a warning. Within 14 days of expiry the scan prints a notice.

A malformed exception never suppresses anything. A bad ignore-file entry or
policy rule stops the scan before anything is scanned, with an error naming the
entry, whether or not the run includes IaC paths; an inline marker with a
malformed `expires=` is reported and not applied.

## Where exceptions come from

| Source | Declared in | Who controls it | Recorded as |
|---|---|---|---|
| Inline marker | the IaC file, on or above the line | anyone who can commit the file | `source: inline`, `origin: path:line` |
| Ignore file | `.agent-bom-ignore.yaml` or `--ignore-file` | repository owners | `source: ignore_file`, `origin: file#entry` |
| Policy `allow` rule | `--policy` file | whoever owns the policy | `source: policy`, `origin: policy:name#rule` |
| Tenant exception | `POST /v1/exceptions`, approved by a second admin | the platform's admins | `source: tenant`, `approved_by` |

### Inline marker

Put the marker on the offending line or the line directly above it. `expires=`
and `owner=` are optional and come before the reason:

```yaml
securityContext:
  # agent-bom: ignore[K8S-001] expires=2026-12-31 owner=platform-team node debugger needs host access
  privileged: true
```

Several rule ids can share a marker: `ignore[K8S-001,K8S-006]`. A marker with
no reason suppresses nothing.

### Ignore file

`agent-bom iac` and `agent-bom scan --iac` read `.agent-bom-ignore.yaml` from
the working directory, or the file given with `--ignore-file`. An entry is an
IaC entry when it has `rule`, `resource` or `type: iac`, or when its `id` is an
IaC rule id (`K8S-001`, `TF-SEC-012`, `DOCKER-003`, ...). Vulnerability entries
in the same file keep working as before.

```yaml
ignores:
  # One rule, one directory, until a date
  - rule: K8S-001
    path: "deploy/dev/**"
    reason: "Debug pods in dev need privileged mode"
    owner: platform-team
    expires: 2026-12-31

  # One rule on one declared resource
  - rule: K8S-006
    resource:
      kind: Deployment
      name: legacy-batch
      namespace: jobs
      labels: {team: data}
    reason: "Writes scratch files to the root filesystem; tracked in DATA-142"
    expires: 2027-03-31

  # The vulnerability form still works
  - id: CVE-2024-1234
    reason: "Not exploitable: no user input reaches the parser"
```

| Field | Required | Meaning |
|---|---|---|
| `rule` (or `id`) | yes | IaC rule id, or a glob such as `K8S-*`. A bare `*` needs a `path` or `resource`. |
| `reason` | yes | Why this is accepted. Carried into every export. |
| `path` | no | Glob on the finding's path, relative to the scanned directory or to the working directory. |
| `resource` | no | `kind`, `name`, `namespace` (globs) and `labels` (all must be present). Matches only findings whose resource the parser knows (Kubernetes manifests and rendered Helm charts); it never matches a finding without one. |
| `expires` | no | `YYYY-MM-DD`; the exception applies through that day. |
| `owner` | no | Team or person accountable for the exception. |

Unknown keys are rejected so a typo cannot quietly widen or disable an entry.

### Tenant exceptions (API)

On a self-hosted control plane, IaC exceptions use the same request and
four-eyes approval workflow as vulnerability exceptions, scoped to the caller's
tenant:

```bash
curl -X POST "$AGENT_BOM_URL/v1/exceptions" -H "X-API-Key: $REQUESTER_KEY" \
  -H 'Content-Type: application/json' -d '{
    "iac_rule_id": "K8S-001",
    "iac_path": "deploy/ops/*",
    "iac_resource": {"kind": "Pod", "name": "node-debugger"},
    "reason": "Node debugger needs host access (CAB-1182)",
    "expires_at": "2026-12-31T00:00:00Z"
  }'

curl -X PUT "$AGENT_BOM_URL/v1/exceptions/$ID/approve" -H "X-API-Key: $SECOND_ADMIN_KEY"
```

An IaC exception needs an exact rule id, a path or resource scope, a reason and
a bounded, timezone-aware expiry; the requester cannot approve it. Only
approved, unexpired exceptions of the scan's tenant are applied when the API
scans a repository, and when the MCP `scan` tool scans a project directory
(the tenant the MCP server is bound to with `AGENT_BOM_MCP_TENANT_ID`). A revoked
or expired one stops applying at the next scan. These repository scans honour
inline markers and tenant exceptions; they do not read an ignore file from the
scanned repository. If the exception store is unavailable, no tenant exception
applies and the scan records a warning.

## Policy-as-code for IaC

A policy rule is an IaC rule when it sets `"scope": "iac"` or any `iac_*`
condition. IaC rules are never evaluated against vulnerabilities, and the
existing vulnerability rules are never evaluated against IaC findings.

| Condition | Matches |
|---|---|
| `iac_rule` | rule id or glob (`K8S-001`, `K8S-*`) |
| `severity_gte` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `iac_path` | glob on the finding's path |
| `iac_resource_kind`, `iac_resource_name`, `iac_namespace` | globs on the declared resource |
| `iac_labels` | labels the resource must carry |
| `iac_environment` | the finding's environment (below) |

A finding's environment comes from the policy's `environments` map (path globs
per environment) first, then from an `environment` or `env` label on the
resource. A finding with no environment matches no `iac_environment` rule, so
map every deploy directory you want a rule to cover.

| Action | Effect |
|---|---|
| `block` (or `fail`) | fails the scan (exit 1) |
| `warn` | reported, does not fail |
| `allow` | accepts the finding as an exception: needs `reason`, takes optional `owner` and `expires`, and is recorded with `source: policy` |

A `block` rule with `"waivable": false` cannot be bypassed from the repository:
inline markers, ignore-file entries and policy `allow` rules that cover a
finding it matches are rejected (the scan prints `rejected exception`), and the
finding blocks. Only an approved tenant exception can waive it.

Example: block privileged pods in prod, warn in dev, and accept the dev debug
pod explicitly.

```json
{
  "name": "iac-guardrails",
  "environments": {
    "prod": ["deploy/prod/**", "k8s/overlays/prod/**"],
    "dev": ["deploy/dev/**", "k8s/overlays/dev/**"]
  },
  "rules": [
    {
      "id": "no-privileged-prod",
      "description": "Privileged pods are blocked in prod",
      "iac_rule": "K8S-001",
      "iac_environment": "prod",
      "action": "block",
      "waivable": false
    },
    {
      "id": "dev-debugger-ok",
      "iac_rule": "K8S-001",
      "iac_environment": "dev",
      "iac_resource_name": "node-debugger",
      "action": "allow",
      "reason": "Dev node debugger runs privileged by design",
      "owner": "platform-team",
      "expires": "2027-01-31"
    },
    {
      "id": "privileged-dev-warn",
      "description": "Other privileged pods in dev are reviewed",
      "iac_rule": "K8S-001",
      "iac_environment": "dev",
      "action": "warn"
    }
  ]
}
```

```bash
agent-bom iac deploy/ --policy iac-guardrails.json --fail-on-severity high -f sarif -o iac.sarif
```

## Reading the result

```json
"iac_findings": {
  "total": 5,
  "findings": [ ... active findings, the only ones gates see ... ],
  "suppressed": [
    {
      "rule_id": "K8S-001",
      "file_path": "dev/pod.yaml",
      "resource": {"kind": "Pod", "name": "node-debugger", "namespace": "dev", "labels": {}},
      "suppressed": true,
      "suppression": {
        "state": "accepted_risk",
        "reason": "Debug pods in dev need privileged mode",
        "source": "ignore_file",
        "origin": ".agent-bom-ignore.yaml#1",
        "owner": "platform-team",
        "expires": "2026-12-31",
        "expiring_soon": false,
        "approved_by": null,
        "exception_id": "iacx-..."
      }
    }
  ],
  "exceptions": {"accepted": 1, "expired": 0, "expiring_soon": 0, "invalid": 0, "rejected": 0,
                 "by_source": {"ignore_file": 1}, "notices": []},
  "policy": {"policy_name": "iac-guardrails", "failures": [], "warnings": [], "allowed": [], "passed": true}
}
```

Use `--verbose` on the console to list each accepted exception with its reason,
owner and expiry.

## Security notes

Exceptions are a place to hide risk, so the design keeps them auditable:

- no exception without a reason, and nothing malformed is ever applied;
- every accepted finding stays in JSON, SARIF and HTML with who/where/why/until;
- expiry is enforced on every scan, not only when someone remembers;
- `waivable: false` keeps a repository author from waiving an org rule in code;
- tenant exceptions need a second admin, an exact rule and scope, and a bounded
  expiry, and every read and write is scoped to the caller's tenant.

See also: [Cloud Posture and IaC Gates](cloud-posture.md),
[Policy Engine](policy.md).
