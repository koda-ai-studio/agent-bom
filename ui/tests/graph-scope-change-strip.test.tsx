import { fireEvent, render, screen } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import type { GraphEstateChangesResponse } from "@/lib/api-types";
import { GraphScopeChangeStrip } from "@/components/graph-scope-change-strip";
const changes = (status="comparable") => ({ sources:[{
  scope_id:"repo", comparison:{ status, reason:status === "comparable" ? null : "incomplete_collection" },
  kev_change:{ old:2,new:0,delta:-2,basis:"issue_groups" },
  nodes_by_entity_type:{ agent:{ added:2,removed:1,changed:0 }, server:{ added:0,removed:1,changed:0 } },
  highlights:{ new_attack_paths:{ status:"complete",count:1 },removed_attack_paths:{ status:"complete",count:0 } },
}],new_sources:[],pagination:{ has_more:false } }) as unknown as GraphEstateChangesResponse;
it("uses exact scoped counts and opens their source detail", () => {
  const onOpen=vi.fn();
  render(<GraphScopeChangeStrip changes={changes()} onOpen={onOpen} />);
  expect(screen.getByText("KEV −2")).toBeVisible();
  expect(screen.getByText("Paths +1 −0")).toBeVisible();
  expect(screen.getByText("Agents +2 −1")).toBeVisible();
  expect(screen.getByText("MCP +0 −1")).toBeVisible();
  fireEvent.click(screen.getByRole("button",{ name:/Open comparable scope changes/ }));
  expect(onOpen).toHaveBeenCalled();
});
it("does not turn partial collection into a decrease or a clean zero", () => {
  render(<GraphScopeChangeStrip changes={changes("unavailable")} onOpen={() => {}} />);
  expect(screen.getByText(/Comparison unavailable/)).toBeVisible();
  expect(screen.queryByText("KEV −2")).toBeNull();
  expect(screen.queryByText("MCP +0 −1")).toBeNull();
});
it("keeps unmaterialized paths and missing KEV evidence unknown", () => {
  const data=changes();data.sources[0]!.kev_change=null;
  data.sources[0]!.highlights.new_attack_paths={ status:"not_materialized",count:0,top:[] };
  render(<GraphScopeChangeStrip changes={data} onOpen={() => {}} />);
  expect(screen.getByText("KEV unavailable")).toBeVisible();
  expect(screen.getByText("Paths unavailable")).toBeVisible();
});
it("shows first observation and bounded pages without inventing additions", () => {
  const data=changes();data.sources=[];data.new_sources=[{}] as typeof data.new_sources;data.pagination.has_more=true;
  render(<GraphScopeChangeStrip changes={data} onOpen={() => {}} />);
  expect(screen.getByText(/First observation/)).toBeVisible();
  expect(screen.getByText(/Loaded scopes only/)).toBeVisible();
});
