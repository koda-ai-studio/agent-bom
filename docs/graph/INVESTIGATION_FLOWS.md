# Investigation flows

Open **Investigation → Explore connections**, select a snapshot, then choose
**Flow**. The view changes reading order without changing relationship direction
or treating ownership as an attack step:

- **Exposure:** endpoint → workload → recorded identity/access relationships.
  Deployment, namespace, cluster and account records appear on context branches.
- **Identity and access:** a principal or role starts the permission investigation.
- **Vulnerability:** workload/image/package context leads to the affected finding.
- **Inventory:** the recorded containment hierarchy remains the primary view.

Click a **Findings** group to expand its loaded finding nodes, then select a
finding to inspect its evidence. Groups count only the loaded, visible findings;
shared findings retain their separate relationships. Groups are display objects,
not new findings or inventory assets. Saved manual layouts and selected attack
paths retain their existing presentation.

An **Internet** context appears only when the resource carries a complete
`network_reachability_assessment` with an `allow` decision, `internet` source
scope, a matching `target_id`/`resource_id`, and nonempty `evidence_refs`.
It describes the recorded snapshot assessment, not a fresh connectivity test.
Public addresses, outbound connections, open firewall rules, or resource names
alone do not qualify. Display context does not upgrade an attack path's receipts,
reachability, or verification status. Existing collectors that do not emit this
assessment will show endpoints without an Internet boundary.

## Kubernetes context

`agent-bom scan --k8s --no-discover -f json --output scan.json` collects read-only workload inventory.
The report's `kubernetes_inventory` includes retained pod/container context and
Ingress/Service/EndpointSlice routing. Controller joins require a matching namespace,
kind, name and owner UID with a controller reference. EndpointSlice links require
matching Service and Pod UIDs and a ready endpoint. Neither record proves network
reachability: routing context remains non-traversable until separate evidence
supports it. A missing read permission leaves collection partial and the missing
collector unevaluable. The shipped reader roles allow `get`/`list` of Services, Ingresses
and EndpointSlices, never Secret values or mutation verbs.

Inspect the JSON and its collection receipts, then open that snapshot in the
control plane to follow its recorded deployment and finding relationships.
Cluster labels alone do not establish a cloud account or cross-vendor identity.
