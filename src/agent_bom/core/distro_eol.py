"""End-of-life dates for OS releases, keyed like the advisory DB release keys.

Small, dated table drawn from each vendor's published lifecycle page (``as of``
below). Only releases whose end of life had already passed on that date are
listed, so no date here is a forecast. A release missing from the table makes
no claim either way.

Every row was checked on ``END_OF_LIFE_AS_OF`` against the endoflife.date API
(``https://endoflife.date/api/<product>.json``); the recorded records live in
``tests/fixtures/distro_eol/endoflife_date_snapshot.json`` and a test holds the
table to them offline. Where the vendor's own announcement disagrees with the
API, the vendor date is used and the row cites that announcement.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

END_OF_LIFE_AS_OF = date(2026, 11, 2)

_ALPINE = "https://alpinelinux.org/releases/"
_DEBIAN = "https://wiki.debian.org/LTS"
_UBUNTU = "https://ubuntu.com/project/docs/release-team/list-of-releases/"
_UBUNTU_ANNOUNCE = "https://lists.ubuntu.com/archives/ubuntu-announce/"
_RHEL = "https://access.redhat.com/support/policy/updates/errata"
_UBUNTU_SOURCES = {
    "16.04": f"{_UBUNTU_ANNOUNCE}2021-March/000266.html",
    "23.04": f"{_UBUNTU_ANNOUNCE}2024-January/000298.html",
    "23.10": f"{_UBUNTU_ANNOUNCE}2024-July/000303.html",
    "25.04": f"{_UBUNTU_ANNOUNCE}2026-January/000320.html",
    "25.10": f"{_UBUNTU_ANNOUNCE}2026-July/000325.html",
}


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
                (21, "2026-11-01"),
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
                _UBUNTU_SOURCES.get(release, _UBUNTU),
                "Expanded Security Maintenance may still apply under subscription."
                if release.endswith(".04") and int(release[:2]) % 2 == 0
                else "",
            )
            for release, ended in (
                ("16.04", "2021-04-30"),
                ("16.10", "2017-07-20"),
                ("17.04", "2018-01-13"),
                ("17.10", "2018-07-19"),
                ("18.04", "2023-05-31"),
                ("18.10", "2019-07-18"),
                ("19.04", "2020-01-23"),
                ("19.10", "2020-07-17"),
                ("20.04", "2025-05-31"),
                ("20.10", "2021-07-22"),
                ("21.04", "2022-01-20"),
                ("21.10", "2022-07-14"),
                ("22.10", "2023-07-20"),
                ("23.04", "2024-01-25"),
                ("23.10", "2024-07-11"),
                ("24.10", "2025-07-10"),
                ("25.04", "2026-01-15"),
                ("25.10", "2026-07-09"),
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
