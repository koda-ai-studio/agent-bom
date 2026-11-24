"""merge_finding_sla reads only the KEV date from each row; it must match deriving it through finding_sla_fields."""

from __future__ import annotations

import itertools

from agent_bom.core.sla import _kev_due_date, _parse_iso, finding_sla_fields, merge_finding_sla

ROWS = [
    {},
    {"severity": "critical", "first_seen": "2026-01-01T00:00:00Z"},
    {"kev_due_date": "2026-02-01"},
    {"kev_due_date": "2026-02-01T00:00:00+00:00", "sla_due_at": "2026-03-01T00:00:00Z", "sla_due_at_source": "explicit"},
    {"evidence": {"kev_due_date": "2026-01-15"}, "severity": "high"},
    {"evidence": {"kev_due_date": "not a date"}},
    {"kev_due_date": None, "evidence": {"kev_due_date": "2026-04-01T12:00:00+02:00"}},
    {"sla_due_at": "2026-05-01T00:00:00Z", "sla_due_at_source": "legacy-tool"},
]


def test_kev_helper_matches_the_full_derivation_for_every_row_shape() -> None:
    for row in ROWS:
        assert _kev_due_date(row) == _parse_iso(finding_sla_fields(row).get("kev_due_date"))


def test_merge_is_unchanged_for_every_pair() -> None:
    def reference(payload, previous, first_seen):
        from agent_bom.core.sla import carry_finding_sla

        merged = carry_finding_sla(payload, previous)
        kevs = [v for row in (payload, previous) if (v := _parse_iso(finding_sla_fields(row).get("kev_due_date"))) is not None]
        if kevs:
            merged["kev_due_date"] = min(kevs).isoformat()
        merged["first_seen"] = first_seen
        merged.update(finding_sla_fields(merged))
        return merged

    for payload, previous in itertools.product(ROWS, repeat=2):
        assert merge_finding_sla(payload, previous, first_seen="2026-01-01T00:00:00Z") == reference(
            payload, previous, "2026-01-01T00:00:00Z"
        )
