"""An offline NVD 2.0 ``lastModified`` endpoint over a fixed pool of CVEs.

It honours ``lastModStartDate``/``lastModEndDate`` (inclusive), returns each
range oldest-first (NVD has no sort parameter) and pages by
``startIndex``/``resultsPerPage``, so tests can tell newest-first walking from
a single oldest-first window.
"""

from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse


def nvd_cve(cve_id: str, modified: datetime) -> dict:
    stamp = modified.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
    return {
        "cve": {
            "id": cve_id,
            "published": stamp,
            "lastModified": stamp,
            "descriptions": [{"lang": "en", "value": f"NVD CVE {cve_id}"}],
            "metrics": {
                "cvssMetricV31": [
                    {"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}}
                ]
            },
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
        }
    }


def _ts(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.000").replace(tzinfo=timezone.utc)


class FakeNvdWindow:
    def __init__(self, pool: list[tuple[str, datetime]]) -> None:
        self.pool = sorted(pool, key=lambda item: item[1])
        self.calls: list[dict[str, str]] = []
        self.served: list[str] = []

    def __call__(self, url: str, *, timeout: float = 60, headers: dict | None = None) -> dict:
        query = {key: values[0] for key, values in parse_qs(urlparse(url).query).items()}
        self.calls.append(query)
        if "lastModStartDate" not in query:
            return {"totalResults": 0, "vulnerabilities": []}
        start, end = _ts(query["lastModStartDate"]), _ts(query["lastModEndDate"])
        inside = [(cve_id, modified) for cve_id, modified in self.pool if start <= modified <= end]
        first, per = int(query["startIndex"]), int(query["resultsPerPage"])
        page = inside[first : first + per]
        self.served.extend(cve_id for cve_id, _ in page)
        return {
            "resultsPerPage": per,
            "startIndex": first,
            "totalResults": len(inside),
            "vulnerabilities": [nvd_cve(cve_id, modified) for cve_id, modified in page],
        }
