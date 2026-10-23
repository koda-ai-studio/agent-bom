#!/usr/bin/env python3
"""Run agent-bom's DCM scanner against agent-bom's own DCM migrations.

Proves the scanner is alive, its rules fire on real SQL, and the repository's
own migration files are clean (or surface known findings explicitly).
"""

from __future__ import annotations

from pathlib import Path

from agent_bom.iac.dcm import is_dcm_migration, scan_dcm_migration

DCM_DIR = Path("deploy/snowflake/native-app/dcm")
# DCM-001 (GRANT MANAGE GRANTS) is expected in V001; any other critical
# finding in our own migrations is a regression.
EXPECTED_CRITICAL_RULES = frozenset({"DCM-001"})


def main() -> int:
    files = sorted(p for p in DCM_DIR.rglob("*.sql") if is_dcm_migration(p))
    if not files:
        raise SystemExit(f"No DCM migrations found in {DCM_DIR} — scanner or migration path broken")

    findings = [f for path in files for f in scan_dcm_migration(path)]
    print(f"DCM self-check: {len(files)} migration(s) scanned, {len(findings)} finding(s)")
    for f in findings:
        print(f"  {f.severity.upper()} {f.rule_id} {Path(f.file_path).name}:{f.line_number}: {f.title}")

    unexpected = [f for f in findings if f.severity == "critical" and f.rule_id not in EXPECTED_CRITICAL_RULES]
    if unexpected:
        print("FAIL: unexpected critical findings in DCM migrations:")
        for f in unexpected:
            print(f"  {f.rule_id} {f.file_path}:{f.line_number}")
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
