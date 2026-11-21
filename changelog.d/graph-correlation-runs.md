### Fixed

- Link a workload to the image whose digest it pins with one evidenced `runs` edge, so an IaC deployment and an SBOM/image scan of the same digest correlate; packages stay under the image and the image is no longer a second attack-path entry for the same CVE occurrence.
- Every node a graph route serializes now carries `semantic_layer` (recorded layer, else the kind's legend layer), and the summary view keeps `attributes.internet_exposed`, folding in the risk-context verdict, so the graph can group and badge nodes from the API alone.
- The reference evidence lab no longer copies the SBOM image's packages onto the IaC deployment; correlation joins them over the digest-proven `runs` hop, whose receipt now names both observing scans so the workload's CVE path stays likely.
- Graph rollups count a resource as internet-exposed when its risk-context verdict says so, so a raw provider flag such as `publicly_accessible` reaches `exposed_count` the same way it reaches the node.
