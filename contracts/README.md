# agent-bom Contracts

This directory contains versioned integration contracts for downstream
dashboards, SIEM pipelines, evidence exports, and procurement review.

The current stable family is [`v1`](./v1/README.md). v1 contracts are additive:
new optional fields may be added in minor releases, but required fields and
field meanings must not be removed or repurposed without a v2 contract.

[`v2`](./v2/README.md) holds the contracts that needed such a change. The v2
JSON scan report (`schema_version: "2.0"`) carries the same evidence as v1, with
each shared record written once and referenced by ID, and expands exactly back
to the v1 report.

Deprecation: in 0.115.0 `scan -f json` still writes the v1 report by default and
`--report-format v2` opts in; scan pushes already use v2 when the control plane
accepts it. 0.116.0 makes v2 the default for `-f json`; `--report-format v1`
(alias `legacy`) will keep writing v1. An interactive `scan -f json -o <file>`
prints a one-line notice of this to stderr; CI, `--log-json`, `-q` and callers
that already chose `--report-format` do not see it.
