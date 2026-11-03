import { fireEvent, render, screen } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { GraphRepositoryChanges } from "@/components/graph-repository-changes";

it("opens semantic changes in the snapshot that actually contains the entity", () => {
  const open = vi.fn();
  render(<GraphRepositoryChanges change={{status:"complete", ref:"refs/heads/main", counts:{workspace_packages:{added:0,removed:1},dbt_models:{added:1,removed:0},pipelines:{added:0,removed:0}},
    rows:[{id:"old-package",label:"payments",kind:"workspace_packages",change:"removed",scan_id:"previous"}],
    files_with_new_findings:{count:0,status:"complete",rows:[]},rows_truncated:true}} onOpenDiff={open} />);
  expect(screen.getByText("Workspace packages +0 −1")).toBeInTheDocument();
  const link=screen.getByRole("link",{name:/payments/i,hidden:true});
  expect(link.getAttribute("href")).toContain("previous");
  fireEvent.click(screen.getByRole("button",{name:"Open full repository diff",hidden:true}));
  expect(open).toHaveBeenCalledOnce();
});

it("does not present missing ref evidence as zero repository changes", () => {
  render(<GraphRepositoryChanges change={{status:"unavailable",reason:"repository_ref_unavailable"}} onOpenDiff={()=>{}} />);
  expect(screen.getByText(/Repository comparison unavailable/)).toBeInTheDocument();
  expect(screen.queryByText(/Workspace packages/)).toBeNull();
});
