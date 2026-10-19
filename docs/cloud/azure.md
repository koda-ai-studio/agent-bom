# Azure connection reference

Use this guide for the provider grant, collected evidence and coverage limits.
Return to [cloud connections](../CLOUD_CONNECT.md) for shared onboarding.

## 4. Azure — connect with the credential you already have

**Grant** (read-only, built-in): assign **`Reader`** (and **`Security Reader`**
for Defender posture) at the subscription, or at the **tenant root management
group** to cover every subscription at once.

**Authenticate** via `DefaultAzureCredential` — no password, pick one:
- `az login` (cached CLI token), or
- a service principal with a **certificate** (not a secret), or
- a system/user-assigned **managed identity**, or
- workload identity federation (Kubernetes).

```bash
export AGENT_BOM_AZURE_INVENTORY=1
export AGENT_BOM_AZURE_ALL_SUBSCRIPTIONS=1   # fan out across the tenant
agent-bom agents --preset enterprise --azure
```

**What it reads:** storage accounts, VMs, AKS, App Services, disks, NSGs,
managed identities + **RBAC role assignments** (CIEM edges), Key Vaults,
container registries, Cosmos/SQL/PostgreSQL/MySQL, VNets/public-IPs/load
balancers/Front Door/API Management, Event Hubs/Service Bus/Redis,
**management groups** for hierarchy, and **94 CIS checks**.

**Tenant scale (zero trust at scale):** with `AGENT_BOM_AZURE_ALL_SUBSCRIPTIONS=1`
the connector walks the management-group tree, enumerates every subscription,
and scans each independently — partitioned in the graph by account so thousands
of subscriptions stay separable. A defensive `AGENT_BOM_AZURE_MAX_SUBSCRIPTIONS`
cap (default 500) bounds blast radius.

> **Mass-onboarding grant.** Rather than assigning `Reader` per subscription,
> assign it **once at a management group** (the tenant root covers everything)
> so a single assignment covers every subscription under it — the Azure analogue
> of the AWS Organizations StackSet (§3) and the GCP org/folder binding (§5). The
> `connect-azure` module does this with `scope_override` set to a management-group
> ID (`/providers/Microsoft.Management/managementGroups/<id>`); the assignment
> stays read-only (`Reader` + optional `Security Reader`).

**SDK fragility, handled:** Azure SDKs are per-service distributions, so each is
imported under `try/except ImportError` and degrades to a warning if absent —
one missing package never crashes a scan.

**Secure-by-default provisioning** (`deploy/terraform/connect-azure`): the
optional keyless **federated identity credential** is pinned to an exact
**issuer + subject + audience** (`api://AzureADTokenExchange`). The plan fails if
the subject is empty or contains a wildcard, so only one specific external
workload can exchange a token for the scanner principal — never a wide-open
trust. The GCP module (`deploy/terraform/connect-gcp`) is locked the same way:
Workload Identity Federation cannot be enabled without a scoped
`attribute_condition`, pinned audiences, and a specific `principalSet`, and the
service account gets a unique, non-guessable name.

---
