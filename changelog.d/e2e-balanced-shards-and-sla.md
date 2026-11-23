### CI
- UI E2E shards are balanced by recorded test duration instead of Playwright's count-based `--shard`, which put the slow graph specs in one shard (about 200 s of tests against 62 s in another) and set the merge queue's longest job. The planner assigns every listed test to exactly one shard, weights tests without a recorded duration as the median, and the job fails rather than run the whole suite when a shard's plan is empty. `node ui/scripts/e2e-shard-plan.mjs --record <report.json>` refreshes the timings.

### Performance
- Findings reads derive each SLA deadline once per finding instead of three times when merging with prior history; only the KEV date was needed from the other two derivations.
