"""Repository artifact readers release every descriptor on partial failures."""

import os

import pytest

from agent_bom.parsers.repository import artifacts


@pytest.mark.skipif(os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW"), reason="requires descriptor-relative reads")
@pytest.mark.parametrize("failure", [None, "directory", "file", "fdopen"])
def test_repository_reader_closes_handles_on_every_open_failure(tmp_path, monkeypatch, failure):
    directory = tmp_path / "nested" / "project"
    directory.mkdir(parents=True)
    (directory / "package.json").write_text('{"name":"fixture"}')
    opened = []
    original_open, original_dup, original_fdopen = os.open, os.dup, os.fdopen

    def track_open(path, flags, *args, **kwargs):
        if (failure == "directory" and path == "project") or (failure == "file" and path == "package.json"):
            raise OSError("fixture open failure")
        descriptor = original_open(path, flags, *args, **kwargs)
        opened.append(descriptor)
        return descriptor

    def track_dup(descriptor):
        duplicate = original_dup(descriptor)
        opened.append(duplicate)
        return duplicate

    def wrap_file(*args, **kwargs):
        if failure == "fdopen":
            raise OSError("fixture wrapper failure")
        return original_fdopen(*args, **kwargs)

    reader = artifacts.RepositoryReader(tmp_path)
    with monkeypatch.context() as patch:
        patch.setattr(os, "open", track_open)
        patch.setattr(os, "dup", track_dup)
        patch.setattr(os, "fdopen", wrap_file)
        patch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {track_open})
        result = reader.read("nested/project/package.json")
    leaked = []
    for descriptor in opened:
        try:
            os.fstat(descriptor)
        except OSError:
            continue
        leaked.append(descriptor)
        os.close(descriptor)  # A red run must not leak the test's own descriptors.
    assert opened
    assert not leaked, "repository read left descriptors open after completion"
    if failure:
        assert result is None
        assert reader.unresolved == [{"artifact": "nested/project/package.json", "reason": "invalid_or_unreadable_artifact"}]
    else:
        assert result == '{"name":"fixture"}'
        assert reader.unresolved == []
