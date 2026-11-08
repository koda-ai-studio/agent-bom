import { render, screen } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { FindingLaneTabs } from "@/components/finding-lane-tabs";

it("explains unavailable counts once instead of repeating ambiguous dashes", () => {
  render(<FindingLaneTabs lane="all" approximate={false} onChange={vi.fn()} />);
  expect(screen.getByText("Tab counts are unavailable.")).toBeVisible();
  for (const tab of screen.getAllByRole("tab")) expect(tab).not.toHaveTextContent("—");
});

it("does not describe tab counts that are not shown", () => {
  render(<FindingLaneTabs lane="all" approximate={false} onChange={vi.fn()} />);
  expect(screen.queryByText(/Tab counts: canonical issues/)).toBeNull();
});

it("describes the tab count basis when counts are shown", () => {
  render(<FindingLaneTabs lane="all" counts={{ vuln: 3, cloud: 2 }} approximate={false} onChange={vi.fn()} />);
  expect(screen.getByText(/Tab counts: canonical issues in the current filter scope\./)).toBeVisible();
  expect(screen.queryByText("Tab counts are unavailable.")).toBeNull();
  expect(screen.getByRole("tab", { name: /All findings/ })).toHaveTextContent("5");
});
