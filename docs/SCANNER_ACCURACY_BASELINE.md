# Scanner Accuracy Baseline

This file defines what `agent-bom` can prove before a release and what remains a roadmap item.

For match-confidence tiers, canonical CVE mapping, and NVD key boundaries, see
[VULNERABILITY_MATCHING.md](VULNERABILITY_MATCHING.md).

The machine-readable release artifact is [`accuracy-baseline.json`](accuracy-baseline.json). It is generated with:

```bash
uv run python scripts/generate_accuracy_baseline.py
uv run python scripts/generate_accuracy_baseline.py --check
```

## Release Gate

The current release baseline covers:

- runtime red-team detector false-positive and false-negative accounting
- demo inventory advisory realism, so screenshots and examples do not claim fabricated CVEs
- VEX-suppressed and fixed-verified findings tracked separately from active unresolved risk
- known-vulnerable package regression checks when network tests are enabled

It does not claim a customer-wide real-world FP/FN rate yet. That requires a published quarterly corpus and sampled production-style repositories.

## Required Checks

```bash
uv run pytest tests/test_red_team.py -q
uv run pytest tests/test_demo_inventory_accuracy.py -q
uv run pytest tests/test_accuracy_baseline.py -q -m network
uv run python scripts/generate_accuracy_baseline.py --check
```

## Interpreting States

`active_unresolved` findings count toward posture and policy gates.

`fixed_verified`, `accepted_risk`, `not_affected`, and `false_positive` are
suppression evidence states. `needs_review` is a non-suppressing triage state
for low-confidence or declaration-only findings. These states must remain
visible in audit trails and release evidence, but suppressing states should not
inflate active-risk counts.

### Reading possibly affected counts

Run `agent-bom scan --project . -f json -o scan.json`, then inspect
`summary.total_vulnerabilities` and `summary.total_possibly_affected` separately.
The second count is distinct advisory/package identity pairs requiring review;
it excludes duplicate package observations and does not increase severity totals
or trigger `--fail-on-severity`. Review the `possibly_affected` rows, confirm the
installed version and relevant distribution advisory, then rescan. Older stored
reports without this count show it as unavailable in the dashboard.

Candidate alias lookup can ignore unrelated stale fused aliases without making
the scan partial. Matched advisory warnings and actual advisory-data coverage
gaps still affect completeness; a zero confirmed count does not erase them.
