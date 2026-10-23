"""Bounded, streaming readers for local Claude Code and Codex session histories."""

from __future__ import annotations

import os
from datetime import datetime, timezone

from agent_bom.runtime.agent_sessions import CLAUDE_CODE_SESSIONS, CODEX_SESSIONS, SessionBounds, read_session_calls
from tests._agent_session_fixtures import PROJECT, claude_records, codex_records, make_homes, write_jsonl

SINCE = datetime(2026, 10, 1, tzinfo=timezone.utc)


def test_claude_code_reader_yields_assistant_tool_uses_once(tmp_path):
    calls, stats = read_session_calls(CLAUDE_CODE_SESSIONS, home=make_homes(tmp_path), since=SINCE)

    assert [call.call_id for call in calls] == ["tu-1", "tu-2", "tu-3", "tu-4", "tu-5", "tu-6"]
    assert stats.files_read == 1 and stats.malformed_lines == 0
    mcp = calls[4]
    assert (mcp.server, mcp.tool, mcp.action, mcp.source) == ("github", "create_issue", "mcp", "claude_code")
    assert [call.action for call in calls[:4]] == ["exec", "read", "write", "write"]
    assert calls[0].command.startswith("npm install left-pad")
    assert calls[1].paths == (f"{PROJECT}/.env",)
    assert {call.session_id for call in calls} == {"s-claude-1"}
    assert {call.project_root for call in calls} == {PROJECT}
    assert calls[0].timestamp == "2026-10-20T10:00:00+00:00"


def test_codex_reader_uses_completed_items_and_dedupes_ids(tmp_path):
    calls, stats = read_session_calls(CODEX_SESSIONS, home=make_homes(tmp_path), since=SINCE)

    assert [(call.action, call.tool) for call in calls] == [
        ("exec", "exec"),
        ("exec", "exec"),
        ("write", "apply_patch"),
        ("mcp", "list_issues"),
    ]
    assert calls[0].command == "pip install requests==2.0.0"
    assert calls[2].paths == (f"{PROJECT}/README.md", "/tmp/outside.txt")
    assert calls[3].server == "github"
    assert {call.session_id for call in calls} == {"s-codex-1"}
    assert {call.project_root for call in calls} == {PROJECT}
    assert stats.files_read == 1


def test_malformed_and_oversized_lines_are_skipped_and_counted(tmp_path):
    path = tmp_path / ".claude" / "projects" / "p" / "s.jsonl"
    write_jsonl(path, claude_records()[:2], extra_lines=["{not json", "[1, 2]", '{"type": "assistant", "message": 7}', "x" * 5000])
    calls, stats = read_session_calls(CLAUDE_CODE_SESSIONS, home=tmp_path, since=SINCE, bounds=SessionBounds(max_line_bytes=4096))

    assert [call.call_id for call in calls] == ["tu-1"]
    assert stats.malformed_lines == 2  # invalid JSON and a non-object line
    assert stats.oversized_lines == 1


def test_file_line_and_byte_caps_are_enforced_and_reported(tmp_path):
    for index in range(4):
        write_jsonl(tmp_path / ".claude" / "projects" / "p" / f"s{index}.jsonl", claude_records())
    _, stats = read_session_calls(CLAUDE_CODE_SESSIONS, home=tmp_path, since=SINCE, bounds=SessionBounds(max_files=2))
    assert (stats.files_read, stats.files_skipped_cap) == (2, 2)
    assert stats.truncated is True

    calls, stats = read_session_calls(CLAUDE_CODE_SESSIONS, home=tmp_path, since=SINCE, bounds=SessionBounds(max_lines_per_file=3))
    assert len(calls) == 4 * 2 and stats.lines_capped_files == 4

    _, stats = read_session_calls(CLAUDE_CODE_SESSIONS, home=tmp_path, since=SINCE, bounds=SessionBounds(max_total_bytes=600))
    assert stats.bytes_capped is True and stats.truncated is True
    # Files never opened because the byte budget ran out are skipped, not "read".
    assert stats.files_read == 1 and stats.files_skipped_cap == 3


def test_window_and_project_filters(tmp_path):
    old = claude_records(ts="2026-09-01T10:00:00Z")
    for record in old:
        for block in (record.get("message") or {}).get("content") or []:
            if isinstance(block, dict) and "id" in block:
                block["id"] = "old-" + block["id"]
    make_homes(tmp_path, claude=old + claude_records(), codex=codex_records(cwd="/work/other"))

    calls, stats = read_session_calls(CLAUDE_CODE_SESSIONS, home=tmp_path, since=SINCE)
    assert len(calls) == 6 and stats.out_of_window == 6

    assert read_session_calls(CODEX_SESSIONS, home=tmp_path, since=SINCE, project=PROJECT)[0] == []
    assert len(read_session_calls(CODEX_SESSIONS, home=tmp_path, since=SINCE, project="/work/other")[0]) == 4


def test_files_older_than_window_are_not_opened(tmp_path):
    path = write_jsonl(tmp_path / ".claude" / "projects" / "p" / "old.jsonl", claude_records())
    stale = datetime(2026, 9, 1, tzinfo=timezone.utc).timestamp()
    os.utime(path, (stale, stale))
    calls, stats = read_session_calls(CLAUDE_CODE_SESSIONS, home=tmp_path, since=SINCE)
    assert calls == [] and stats.files_read == 0 and stats.files_skipped_window == 1


def test_missing_history_directories_are_an_empty_read(tmp_path):
    calls, stats = read_session_calls(CODEX_SESSIONS, home=tmp_path, since=SINCE)
    assert calls == [] and stats.files_read == 0 and stats.history_found is False
