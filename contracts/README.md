# agent-bom Contracts

This directory contains versioned integration contracts for downstream
dashboards, SIEM pipelines, evidence exports, and procurement review.

The current stable family is [`v1`](./v1/README.md). v1 contracts are additive:
new optional fields may be added in minor releases, but required fields and
field meanings must not be removed or repurposed without a v2 contract.

[`v2`](./v2/README.md) holds the contracts that needed such a change. From
0.115.0 the JSON scan report is v2 (`schema_version: "2.0"`): the same
evidence, with each shared record written once and referenced by ID, and an
exact expansion back to the v1 report. `--report-format legacy` still writes v1.
