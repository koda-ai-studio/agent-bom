### Fixed

- Preserve API, dashboard, and collector image tags referenced by every published Helm chart during Docker Hub cleanup. Incomplete chart discovery now stops cleanup before deletion, and each run retains the chart reference receipt.
- Upgrade the cleanup workflow installer to the required certificate-trust floor before installing dependencies, and include the installer security contract in affected tests for every workflow change.
