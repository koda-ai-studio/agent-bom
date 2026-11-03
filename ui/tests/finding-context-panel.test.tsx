import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { FindingContextPanel, FindingContextFilter } from "@/components/finding-context-panel";

const get = vi.hoisted(() => vi.fn());
vi.mock("@/lib/api-transport", () => ({ get }));
beforeEach(() => get.mockReset());
it("keeps critical fixture occurrences visible with scoped review links", async () => {
  get.mockResolvedValue({ count: 3, approximate: false, warnings: [], contexts: [
    { context: "test", total: 2, severity: { critical: 2 } },
    { context: "unclassified", total: 1, severity: { high: 1 } },
  ] });
  render(<FindingContextPanel />);
  expect(await screen.findByText("Tests and fixtures")).toBeTruthy();
  expect(screen.getByText("2 critical · 0 high")).toBeTruthy();
  expect(screen.getByText(/Headline scores include all contexts/)).toBeTruthy();
  expect(screen.getAllByRole("link")[0]?.getAttribute("href")).toContain("lane=all&path_context=test");
  expect(screen.queryByText(/production findings/i)).toBeNull();
});
it("labels bounded counts as partial, never as a clean assessment", async () => {
  get.mockResolvedValue({ count: 1, approximate: true, warnings: ["bounded"], contexts: [{ context: "example", total: 1, severity: {} }] });
  render(<FindingContextPanel />);
  expect(await screen.findByText("At least 1")).toBeTruthy();
  expect(screen.getByRole("status").textContent).toContain("partial");
});
it("provides an explicit all-context reset", () => {
  const onChange = vi.fn();
  render(<FindingContextFilter value="test" onChange={onChange} />);
  fireEvent.change(screen.getByLabelText("Path context"), { target: { value: "" } });
  expect(onChange).toHaveBeenCalledWith("");
});
