"""End-of-life dates for OS releases, keyed like the advisory DB release keys.

Small, dated table drawn from each vendor's published lifecycle page (``as of``
below). Only releases whose end of life had already passed on that date are
listed, so no date here is a forecast. A release missing from the table makes
no claim either way.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

END_OF_LIFE_AS_OF = date(2026, 11, 2)

_ALPINE = "https://alpinelinux.org/releases/"
_DEBIAN = "https://wiki.debian.org/LTS"
_UBUNTU = "https://ubuntu.com/about/release-cycle"
_RHEL = "https://access.redhat.com/support/policy/updates/errata"


@dataclass(frozen=True)
class EndOfLife:
    release: str  # advisory DB release key, e.g. "alpine:v3.14"
    ended: date
    source: str
    note: str = ""


def _table() -> dict[str, EndOfLife]:
    rows = [
        *(
            EndOfLife(f"alpine:v3.{minor}", date.fromisoformat(ended), _ALPINE)
            for minor, ended in (
                (10, "2021-05-01"),
                (11, "2021-11-01"),
                (12, "2022-05-01"),
                (13, "2022-11-01"),
                (14, "2023-05-01"),
                (15, "2023-11-01"),
                (16, "2024-05-23"),
                (17, "2024-11-22"),
                (18, "2025-05-09"),
                (19, "2025-11-01"),
                (20, "2026-04-01"),
            )
        ),
        # Debian: end of LTS, the last date any Debian security fix was published.
        *(
            EndOfLife(f"debian:{major}", date.fromisoformat(ended), _DEBIAN)
            for major, ended in (("8", "2020-06-30"), ("9", "2022-06-30"), ("10", "2024-06-30"), ("11", "2026-08-31"))
        ),
        # Ubuntu: end of standard support. LTS releases may still receive fixes
        # under a paid Expanded Security Maintenance subscription.
        *(
            EndOfLife(
                f"ubuntu:{release}",
                date.fromisoformat(ended),
                _UBUNTU,
                "Expanded Security Maintenance may still apply under subscription."
                if release.endswith(".04") and int(release[:2]) % 2 == 0
                else "",
            )
            for release, ended in (
                ("16.04", "2021-04-30"),
                ("18.04", "2023-05-31"),
                ("20.04", "2025-05-31"),
                ("22.10", "2023-07-20"),
                ("23.04", "2024-01-25"),
                ("23.10", "2024-07-11"),
                ("24.10", "2025-07-10"),
            )
        ),
        EndOfLife(
            "red hat:enterprise_linux:7",
            date(2024, 6, 30),
            _RHEL,
            "Extended Life-cycle Support may still apply under subscription.",
        ),
    ]
    return {row.release: row for row in rows}


_END_OF_LIFE = _table()


def end_of_life_release(release_key: str, *, today: date | None = None) -> EndOfLife | None:
    """Return the end-of-life record for *release_key* when it has ended on *today*."""
    record = _END_OF_LIFE.get(release_key)
    if record is None:
        return None
    return record if record.ended <= (today or date.today()) else None


def end_of_life_detail(record: EndOfLife, package_count: int) -> str:
    """Operator-facing wording for an end-of-life release."""
    label = record.release.replace("red hat:enterprise_linux:", "rhel:").replace(":v", " ").replace(":", " ")
    extra = f" {record.note}" if record.note else ""
    return (
        f"{label} reached end of life on {record.ended.isoformat()} (source: {record.source}). "
        f"{package_count} package(s) come from a release that no longer receives security fixes, so newly "
        "disclosed vulnerabilities may go unpatched and untracked by advisory feeds; a low or zero count is "
        f"not a clean bill of health. Move to a supported release.{extra}"
    )
