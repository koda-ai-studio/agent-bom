# Cloud posture grading

Cloud scans grade the controls they could evaluate and say how much that covers.
The worst and the best account must never look alike, and a grade must never
claim more than the evidence behind it.

## Control statuses

| Status | Meaning | Score |
| --- | --- | --- |
| `pass` | At least one resource was inspected and none offends, or the account-level setting is correct. | Counts as passed |
| `fail` | A resource or setting offends the control. | Counts as failed |
| `error` | The check could not finish (denied read, API failure). Any unrecognized status is treated the same way. | Unknown: stays in the denominator, because it cannot be assumed fine |
| `no_data` | The state could not be determined, such as a disabled API or disabled billing. | Excluded |
| `not_applicable` | Enumeration succeeded and nothing is in scope for this control, or the control is a manual one. | Excluded |

A check with **no resources is `not_applicable`, never `pass`**: "all 0 instances
are encrypted" is not evidence. This follows the XCCDF `notapplicable` result that
CIS tooling reports. `no_data` is kept for "we could not look". A control whose
absence is the point, such as "no root access keys", or a security-group check with
groups present, keeps its real `pass`. A control that requires something to exist,
such as a multi-region trail, still fails when it is missing.

## Score and coverage

```text
score    = passed / (passed + failed + unknown)
coverage = (passed + failed) / (passed + failed + unknown + no_data)
```

This follows the common `pass / (pass + fail + unknown)` model. For example, 15
passed, 39 failed, 1 errored, 1 no data and 3 not applicable scores
`15 / 55 = 27.3` with coverage `54 of 56`, and reads
`F (partial, 54 of 56 evaluated)`.

Letters come from the standard grade thresholds, which adopters can override with
`AGENT_BOM_POSTURE_POLICY`.

## When a grade is partial, capped or withheld

| Situation | Result |
| --- | --- |
| Every applicable control evaluated, no collection gaps | Plain letter, such as `A` |
| Any control errored or had no data, or a collector warned or partly failed | Letter with `(partial, N of M evaluated)`; `partial: true` |
| Partial and the score reaches the A band | Capped at `B`. The score stays the true pass rate. Unevaluated controls may hold failures, so the top band needs a complete assessment |
| Under 50% of applicable controls evaluated (`MIN_CONTROL_COVERAGE`) | `N/A` with the reason; `no_data: true` |
| Nothing evaluated, or the collector fully failed | `N/A` with the reason; `no_data: true` |

A partial scan never reads as clean: the headline shows `PARTIAL COVERAGE`, not
`CLEAN`, and reports withhold the "no vulnerabilities found" line.

Scans that also hold package or MCP evidence use the lower of the weighted scan
score and the cloud pass rate, and the same cap applies. Scans with no cloud evidence
are graded exactly as before.

## Disabled services

A disabled GCP API (`SERVICE_DISABLED`) during discovery means the project does not
use that service. It is recorded in `scan_run.issues` as `cloud_service_not_in_use`
with `affects_coverage: false`. It is not a warning and does not fail the scan.
Disabled billing and missing permissions remain coverage gaps.

If discovery fails but the provider's controls were evaluated, the scan outcome is
`partial`, not `failed`. A provider with no evaluated controls and a failed collector
stays `failed`.

## Where the grade appears

| Surface | Fields |
| --- | --- |
| JSON report | `posture_grade` (letter), `posture_grade_label`, `posture_scorecard.partial`, `posture_scorecard.cloud_controls` |
| SARIF run properties | `posture_grade`, `posture_grade_label` |
| `/v1/overview` `posture`, `/v1/posture` | `grade`, `grade_label`, `partial`, `cloud_controls` |
| Console, HTML, Markdown, PDF, Overview | The label beside the score |

The control plane recomputes the grade from stored control rows with the same code,
so the CLI and API agree on the same data. For a tenant whose current scans hold only
cloud controls, the headline is the control pass rate; ingested compliance-hub
evidence can still lower it. Exit codes are covered in
[CLI Exit Codes](exit-codes.md).
