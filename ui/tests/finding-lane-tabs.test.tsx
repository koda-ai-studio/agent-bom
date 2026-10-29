import { render, screen } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { FindingLaneTabs } from "@/components/finding-lane-tabs";

it("explains unavailable counts once instead of repeating ambiguous dashes", () => {
  render(<FindingLaneTabs lane="all" approximate={false} onChange={vi.fn()} />);
  expect(screen.getByText("Counts are unavailable.")).toBeVisible();
  for (const tab of screen.getAllByRole("tab")) expect(tab).not.toHaveTextContent("—");
});
