"""A registry that cannot be reached is unknown, never proof that a package is absent."""

from __future__ import annotations

from unittest import mock

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.cli._check_support import _detect_ecosystem


class _Response:
    def __init__(self, status_code: int, payload: dict | None = None) -> None:
        self.status_code = status_code
        self._payload = payload or {}

    def json(self) -> dict:
        return self._payload


_PYPI_HIT = _Response(200, {"releases": {"2.32.3": []}})
_NPM_HIT = _Response(200, {"versions": {"0.3.0": {}}})
_ABSENT = _Response(404)


def _registry(pypi, npm):
    def fake_get(url, **_kwargs):
        return pypi if "pypi.org" in url else npm

    return mock.patch("agent_bom.http_client.sync_get", side_effect=fake_get)


@pytest.mark.parametrize(
    ("pypi", "npm"),
    [
        (_PYPI_HIT, None),
        (_PYPI_HIT, _Response(503)),
        (_PYPI_HIT, _Response(429)),
        (None, _NPM_HIT),
        (_Response(500), _NPM_HIT),
    ],
    ids=["npm-timeout", "npm-503", "npm-rate-limited", "pypi-timeout", "pypi-500"],
)
def test_an_unreachable_registry_leaves_the_ecosystem_unresolved(pypi, npm) -> None:
    with _registry(pypi, npm):
        assert _detect_ecosystem("requests") is None


def test_a_definite_404_still_resolves_the_other_registry() -> None:
    with _registry(_PYPI_HIT, _ABSENT):
        assert _detect_ecosystem("requests") == "pypi"
    with _registry(_ABSENT, _NPM_HIT):
        assert _detect_ecosystem("left-pad") == "npm"


def test_check_without_a_version_fails_loudly_when_npm_times_out() -> None:
    with _registry(_PYPI_HIT, None):
        result = CliRunner().invoke(main, ["check", "requests"])
    assert result.exit_code == 2
    assert result.stdout == ""
    assert "--ecosystem" in result.stderr
