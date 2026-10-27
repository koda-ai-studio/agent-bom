"""A daemon config ID must never be queried as a Docker Hub repository."""

from contextlib import contextmanager
from unittest.mock import Mock

from agent_bom.image import _daemon_supply_chain, _record_daemon_inspect
from agent_bom.image_evidence import collect_image_evidence


def test_config_id_uses_repository_qualified_observed_digest(monkeypatch):
    digest = "sha256:" + "a" * 64
    observed = []

    @contextmanager
    def client(ref, *args):
        observed.append(ref)
        yield Mock()

    monkeypatch.setattr("agent_bom.image.open_client", client)
    monkeypatch.setattr("agent_bom.image.discover_supply_chain", lambda *a: None)
    monkeypatch.setattr("agent_bom.image.is_offline", lambda: False)
    with collect_image_evidence("sha256:" + "b" * 64):
        _record_daemon_inspect({"RepoDigests": ["agentbom/agent-bom@" + digest]})
        _daemon_supply_chain("sha256:" + "b" * 64, None, None)
    assert len(observed) == 1
    assert observed[0].repository == "agentbom/agent-bom"
    assert observed[0].digest == digest


def test_ambiguous_config_id_does_not_guess_registry(monkeypatch):
    client = Mock()
    monkeypatch.setattr("agent_bom.image.open_client", client)
    monkeypatch.setattr("agent_bom.image.is_offline", lambda: False)
    with collect_image_evidence("sha256:" + "b" * 64) as evidence:
        _record_daemon_inspect({"RepoDigests": ["one/app@sha256:" + "a" * 64, "two/app@sha256:" + "a" * 64]})
        _daemon_supply_chain(evidence.reference, None, None)
        assert evidence.signature["status"] == "unknown"
    client.assert_not_called()


def test_named_image_selects_its_own_digest_and_rejects_mismatch():
    from agent_bom.image_evidence.daemon import daemon_registry_reference

    digest = "sha256:" + "a" * 64
    aliases = ["other/app@" + digest, "docker.io/team/app@" + digest, "team/app@" + digest]
    selected = daemon_registry_reference("team/app:latest", aliases)
    assert selected and selected.repository == "team/app" and selected.digest == digest
    assert daemon_registry_reference("team/app@sha256:" + "b" * 64, aliases) is None
    assert daemon_registry_reference("missing/app:latest", aliases) is None
    assert daemon_registry_reference("team/app:latest", ["team/app:latest", "team/app@sha256:invalid"]) is None
    assert daemon_registry_reference("team/app:latest", aliases * 100) is None
