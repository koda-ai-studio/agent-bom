### Fixed

- Link a workload to the image whose digest it pins with one evidenced `runs` edge, so an IaC deployment and an SBOM/image scan of the same digest correlate; packages stay under the image and the image is no longer a second attack-path entry for the same CVE occurrence.
