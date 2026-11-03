"""Local ref evidence never follows worktree gitdir files outside the repository."""

from agent_bom.parsers import summarize_project_inventory
from tests.test_repository_dbt_lineage import put


def test_local_branch_and_commit_are_recorded_without_git_execution(tmp_path):
    put(tmp_path, ".git/HEAD", "ref: refs/heads/main\n")
    put(tmp_path, ".git/refs/heads/main", "a" * 40 + "\n")
    context = summarize_project_inventory(tmp_path, {})["repository_context"]
    assert context["ref"] == "refs/heads/main"
    assert context["revision"] == "a" * 40
    assert context["ref_status"] == "recorded"


def test_external_gitdir_and_unsafe_ref_are_not_followed(tmp_path):
    put(tmp_path, ".git", "gitdir: /outside/private/path\n")
    context = summarize_project_inventory(tmp_path, {})["repository_context"]
    assert context["ref"] == "unrecorded"
    assert context.get("revision") is None
    (tmp_path / ".git").unlink()
    put(tmp_path, ".git/HEAD", "ref: ../../outside\n")
    context = summarize_project_inventory(tmp_path, {})["repository_context"]
    assert context["ref"] == "unrecorded"
