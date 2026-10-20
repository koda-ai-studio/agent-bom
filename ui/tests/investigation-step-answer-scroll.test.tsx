import { render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { InvestigationLifecyclePanel } from "@/components/investigation-lifecycle";
import type { AttackPath } from "@/lib/graph-schema";

const path = {
  source: "agent:a", target: "vuln:CVE-1", hops: ["agent:a", "vuln:CVE-1"], edges: [], composite_risk: 9,
  summary: "", credential_exposure: [], tool_exposure: [], vuln_ids: ["CVE-1"],
} as AttackPath;

const props = { path, nodeById: new Map(), scanId: "current-estate:t", tenantId: "t", snapshotGeneration: null };
const scrollIntoView = vi.fn();
let top = -400;

beforeEach(() => {
  scrollIntoView.mockReset();
  Element.prototype.scrollIntoView = scrollIntoView;
  vi.spyOn(Element.prototype, "getBoundingClientRect").mockImplementation(() => ({ top, bottom: top + 200, left: 0, right: 0, width: 0, height: 200, x: 0, y: top, toJSON: () => ({}) }));
});
afterEach(() => { vi.restoreAllMocks(); });

describe("choosing an investigation step shows its answer", () => {
  it("scrolls the Fix answer into view when it renders above the viewport", () => {
    top = -400;
    const { rerender } = render(<InvestigationLifecyclePanel step="path" {...props} />);
    rerender(<InvestigationLifecyclePanel step="fix" {...props} />);
    expect(screen.getByRole("region", { name: "Fix · CVE-1" })).toBeInTheDocument();
    expect(scrollIntoView).toHaveBeenCalledTimes(1);
    expect(scrollIntoView.mock.calls[0]![0]).toMatchObject({ block: "start" });
  });

  it("brings up an answer that starts in the lower half and runs off the bottom", () => {
    top = 600;
    const { rerender } = render(<InvestigationLifecyclePanel step="path" {...props} />);
    rerender(<InvestigationLifecyclePanel step="fix" {...props} />);
    expect(scrollIntoView).toHaveBeenCalledTimes(1);
  });

  it("leaves the page alone when the answer is already visible", () => {
    top = 120;
    const { rerender } = render(<InvestigationLifecyclePanel step="path" {...props} />);
    rerender(<InvestigationLifecyclePanel step="fix" {...props} />);
    expect(scrollIntoView).not.toHaveBeenCalled();
  });

  it("does not move the page for a step that arrives with the URL", () => {
    top = -400;
    render(<InvestigationLifecyclePanel step="fix" {...props} />);
    expect(scrollIntoView).not.toHaveBeenCalled();
  });
});
