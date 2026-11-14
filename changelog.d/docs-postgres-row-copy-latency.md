### Docs
- Performance and sizing and the benchmark notes give three-run runner medians and ranges at 1,000 and 5,000 agents on both backends, with the PostgreSQL row copy against the release before: the 5,000-agent PostgreSQL graph p95 fell from 7.0 s to 2.4 s, still above the 2 s steady-state target, and the 1,000-agent median from 1.08 s to 0.74 s.
