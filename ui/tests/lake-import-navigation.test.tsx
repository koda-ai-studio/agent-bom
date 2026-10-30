import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { parseTab } from "@/components/connections/catalog";
import { HubTabs } from "@/components/connections/connect-workflow";

describe("Lake import entry point", () => {
  it("opens the same import workflow from a shared Connections URL", () => {
    expect(parseTab("imports", true)).toBe("imports");
    expect(parseTab("imports", false)).toBe("imports");
  });

  it("makes imports reachable through the Connections navigation", () => {
    const onChange = vi.fn();
    render(<HubTabs tab="connect" onChange={onChange} connectCount={3} sourceCount={0} />);
    fireEvent.click(screen.getByRole("tab", { name: "Lake imports" }));
    expect(onChange).toHaveBeenCalledWith("imports");
  });
});
