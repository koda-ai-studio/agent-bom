### Docs

- The real-repository accuracy page is now reproducible: `scripts/measure_real_repo_accuracy.py` downloads each listed repository at a pinned commit, scans it, builds an independent OSV ground truth from its lockfiles, and writes per-repository results. The page reports the latest measurement, its commits, and the manifests that cannot be independently verified.
