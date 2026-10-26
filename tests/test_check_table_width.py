"""`agent-bom check` vulnerability table stays readable on an 80-column terminal."""

from __future__ import annotations

from io import StringIO

from rich.console import Console

from agent_bom.cli._check_command import CheckRun, _render_vulnerability_table
from agent_bom.models import Severity, Vulnerability


def test_check_table_fits_80_columns_with_a_readable_summary() -> None:
    buf = StringIO()
    run = CheckRun(
        package_spec="lodash@4.17.20",
        ecosystem="npm",
        quiet=False,
        no_color=True,
        output_format="console",
        output_path=None,
        exit_zero=False,
        enrich=False,
        offline=True,
        fail_on_severity=None,
        nvd_api_key=None,
        console=Console(file=buf, width=80, force_terminal=False),
        name="lodash",
        version="4.17.20",
    )
    run.vulns = [
        Vulnerability(id="GHSA-35jh-r3h4-6jhm", summary="Command Injection in lodash", severity=Severity.HIGH, fixed_version="4.17.21"),
        Vulnerability(id="CVE-2020-28500", summary="Regular Expression Denial of Service (ReDoS) in lodash", severity=Severity.MEDIUM),
    ]
    _render_vulnerability_table(run)
    lines = buf.getvalue().splitlines()
    assert all(len(line) <= 80 for line in lines)
    assert any("Command Injection in" in line for line in lines), "\n".join(lines)
    assert any("GHSA-35jh-r3h4-6jhm" in line for line in lines)
