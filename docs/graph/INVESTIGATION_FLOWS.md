# Investigation flows

Open **Investigation → Explore connections**, select a snapshot, then choose
**Flow**. The view changes reading order without changing relationship direction
or treating ownership as an attack step:

- **Exposure:** endpoint → workload → recorded identity/access relationships.
  The view starts at an Ingress, a LoadBalancer or NodePort Service, or a target
  with an assessed Internet ingress. A pod's controllers (ReplicaSet, Deployment)
  follow the pod, because Kubernetes records identity and secret access on the
  controller. The owner link stays drawn in its recorded direction.
- **Identity and access:** a principal or role starts the permission investigation.
- **Vulnerability:** workload → image → package → finding.
- **Inventory:** the recorded containment hierarchy remains the primary view.

The primary path runs along the top row, with other flow nodes and context in
rows beneath it. Records that are not flow steps stay on the map with fainter
edges.

A flow step follows a traversable relationship. Two kinds of non-traversable
record are handled differently:

- Kubernetes routes (`exposed_to`) are always recorded as non-traversable, so
  they order the exposure view but stay dashed. They do not prove reachability.
- An identity hop with no usable credential, such as a service account whose
  token is not mounted, does not advance the flow. The identity stays in context
  and its edge says **Token not mounted**.

ClusterIP and ExternalName Services are never exposure entries, and a Service with
no recorded type is not treated as one. When no recorded Ingress routes to them,
they appear in context as internal, and hovering their route reads **Routes in
cluster to**. A recorded Ingress routing to a ClusterIP Service keeps that Service
in sequence. The underlying relationship remains the recorded `exposed_to`.

## When a flow does not apply

The control never shows a flow it did not apply:

- A flow with nothing to show is disabled and says what is missing, such as
  **Vulnerability (no findings)**.
- **Automatic** names the flow on screen, or reads **current layout** or
  **connection preview** when none is applied. It does not rearrange a graph of 24
  or fewer nodes with no endpoint, account or cluster.
- Maps of more than 24 nodes open as a small connection preview, with tall ranks
  wrapped so no card overlaps another. Choosing a flow opens the full map, and
  availability is judged on everything loaded.
- A full map of more than 24 nodes that no flow fits reads as **Automatic ·
  Connections**. It starts from the root that reaches the most and runs along the
  top row to the most severe finding it reaches, or to its deepest record. Every
  loaded record stays drawn, nothing is grouped, and the view claims no reachability.
  A note on the canvas says how many nodes are in view and how to see the rest.
- Flows read one canvas page of up to 100 nodes. The nodes a flow reads in order
  are kept on the first page, so paging cannot drop its entry. Above 100 nodes the
  path still opens framed, but the rows beneath it would be too tall to scan. Maps
  drawn as the WebGL overview, maps with grouped items, an edited layout and a
  saved layout disable the control and give the reason on screen.

A whole graph that stays legible opens fully framed. Otherwise the view opens on
as much of the primary path as stays legible, and **Fit all** shows the rest. A
phone opens on one card, with **Previous** and **Next** following the path.

Selecting a flow writes it to the `flow` URL parameter, and **Reset view** returns
to Automatic.

Click a **Findings** group to expand its loaded finding nodes, then select a
finding to inspect its evidence. Groups count only the loaded, visible findings;
shared findings retain their separate relationships. Groups are display objects,
not new findings or inventory assets, so they are left out of node counts and
evidence totals. Saved manual layouts and selected attack paths retain their
existing presentation.

An **Internet** context appears only when the resource carries a complete
`network_reachability_assessment` with an `allow` decision, `internet` source
scope, a matching `target_id`/`resource_id`, and nonempty `evidence_refs`.
It describes the recorded snapshot assessment, not a fresh connectivity test.
Public addresses, outbound connections, open firewall rules, or resource names
alone do not qualify. Display context does not upgrade an attack path's receipts,
reachability, or verification status.

No collector in this repository writes `network_reachability_assessment` today, so
scans it produces show endpoints without an Internet boundary. The field is only
read when a pushed report supplies it. Clicking the boundary or its dashed edge
opens the recorded assessment. `evidence_refs` are displayed as recorded: they are
checked for presence, not resolved to the evidence they name.

## Kubernetes context

`agent-bom scan --k8s --no-discover -f json --output scan.json` collects read-only workload inventory.
The report's `kubernetes_inventory` includes retained pod/container context and
Ingress/Service/EndpointSlice routing. Controller joins require a matching namespace,
kind, name and owner UID with a controller reference. EndpointSlice links require
matching Service and Pod UIDs and an endpoint not marked unready (an unset `ready`
condition counts as ready, as `discovery.k8s.io/v1` specifies). Neither record proves network
reachability: routing context remains non-traversable until separate evidence
supports it. A missing read permission leaves collection partial and the missing
collector unevaluable. The shipped reader roles allow `get`/`list` of Services, Ingresses
and EndpointSlices, never Secret values or mutation verbs.

Inspect the JSON and its collection receipts, then open that snapshot in the
control plane to follow its recorded deployment and finding relationships.
Cluster labels alone do not establish a cloud account or cross-vendor identity.
