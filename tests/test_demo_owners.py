"""Demo owners read as fictional team names, never as masked addresses or "Unassigned".

The API masks any email-shaped owner for every viewer, so a demo owner written
as an address renders as ``v***@e***.invalid``. Team names carry no address and
need no masking; every showcase agent's findings route to its team.
"""

from __future__ import annotations

from types import SimpleNamespace

from agent_bom.demo_estate.enterprise_findings import _TRIAGE_OWNER_BY_DOMAIN
from agent_bom.demo_estate.showcase_constants import SHOWCASE_AGENTS
from agent_bom.demo_estate.showcase_owners import SHOWCASE_AGENT_OWNERS, assign_showcase_owners
from agent_bom.security import mask_email


def test_triage_owners_are_team_names_the_api_leaves_readable():
    for owner in _TRIAGE_OWNER_BY_DOMAIN.values():
        assert "@" not in owner
        assert mask_email(owner) == owner


def test_every_showcase_agent_has_a_team():
    assert set(SHOWCASE_AGENT_OWNERS) == set(SHOWCASE_AGENTS)
    assert all("@" not in team and team.endswith("team") for team in SHOWCASE_AGENT_OWNERS.values())


def test_showcase_findings_route_to_their_agent_team_and_keep_explicit_owners():
    rows = [
        SimpleNamespace(owner=None, agent="langchain-service"),
        SimpleNamespace(owner="Existing team", agent="cursor"),
        SimpleNamespace(owner=None, agent="not-a-showcase-agent"),
    ]
    assign_showcase_owners(rows, agent_of=lambda row: row.agent)
    assert [row.owner for row in rows] == [SHOWCASE_AGENT_OWNERS["langchain-service"], "Existing team", None]
