### Fixed

- Preserve API, dashboard, and collector image tags referenced by every published Helm chart during Docker Hub cleanup. Incomplete chart discovery now stops cleanup before deletion, and each run retains the chart reference receipt.
