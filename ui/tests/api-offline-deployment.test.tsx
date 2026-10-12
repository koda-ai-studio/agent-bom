import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ApiOfflineState } from "@/components/api-offline-state";

describe("deployment-aware offline guidance", () => {
  it("explains a control-plane outage without assuming a local installation", () => {
    render(<ApiOfflineState />);
    expect(screen.getByText(/Check that the control plane/)).toBeInTheDocument();
    expect(screen.queryByText(/Run the local stack/)).not.toBeInTheDocument();
    expect(screen.getByText("Local setup instructions").closest("details")).not.toHaveAttribute("open");
    expect(screen.queryByText(/CORS errors/)).not.toBeInTheDocument();
  });
});
