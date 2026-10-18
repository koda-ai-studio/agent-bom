import { describe, expect, it } from "vitest";
import { graphRepositoryContext } from "@/lib/graph-repository-context";

describe("recorded repository identity", () => {
  it("recognizes the backend root marker and exposes recorded slug and host", () => {
    expect(graphRepositoryContext({ nodeType: "directory", attributes: { is_repo_root: true, full_name: "example-org/payments", provider: "github", repo_url: "https://user:secret@github.com/example-org/payments?token=secret#token" } }))
      .toMatchObject({ slug: "example-org/payments", host: "GitHub", remote: "https://github.com/example-org/payments" });
  });
  it("never turns a folder name or URL alone into a repository", () => {
    expect(graphRepositoryContext({ nodeType: "directory", attributes: { path: "github.com/example/repo", repo_url: "https://github.com/example/repo" } })).toBeNull();
  });
  it("keeps missing remote and provider explicit without guessing a vendor", () => {
    expect(graphRepositoryContext({ nodeType: "directory", attributes: { is_repo_root: true } })).toMatchObject({ host: "Remote not recorded", remote: "", slug: "" });
  });
  it("recognizes trust applications but not trust-stamped child files", () => {
    expect(graphRepositoryContext({ nodeType: "container", entityType: "application", attributes: { is_repo_trust: true, provider: "github" } })).not.toBeNull();
    expect(graphRepositoryContext({ nodeType: "sourceFile", attributes: { is_repo_trust: true } })).toBeNull();
  });
  it("keeps scanned revision separate from default branch", () => {
    expect(graphRepositoryContext({ nodeType: "directory", attributes: { is_repo_root: true, default_branch: "main", commit_sha: "abc123" } })).toMatchObject({ branch: "", defaultBranch: "main", commit: "abc123" });
  });
});
