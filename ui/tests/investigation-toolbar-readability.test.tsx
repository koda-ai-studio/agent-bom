import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { InvestigationToolbar } from "@/components/investigation-toolbar";
import { PathPreviewControl } from "@/components/path-preview-control";

describe("focused graph controls", () => {
  it("puts secondary desktop controls in one closed options disclosure", () => {
    render(<InvestigationToolbar embedded compact={false} stepper={null} controls={<button>Labels</button>} layoutControls={<button>Reset layout</button>} />);
    const disclosure = screen.getByLabelText("Graph options").closest("details");
    expect(disclosure).not.toHaveAttribute("open");
    expect(disclosure).toContainElement(screen.getByText("Reset layout"));
  });
  it("does not offer to show all when every loaded path is already shown", () => {
    render(<PathPreviewControl preview shown={3} loaded={3} onShowAll={() => {}} />);
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});
