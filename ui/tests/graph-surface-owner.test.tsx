import { render, screen } from "@testing-library/react";
import { useState } from "react";
import { beforeEach, expect, it, vi } from "vitest";
import { GraphSurface } from "@/app/graph/graph-surface";
const auth = vi.hoisted(() => ({ loading: false, session: { tenant_id: "a", subject: "reader" } as { tenant_id: string; subject: string } | null }));
vi.mock("@/components/auth-provider", () => ({ useAuthState: () => auth }));
vi.mock("@/components/finding-investigation-context", () => ({ FindingInvestigationContext: () => null }));
vi.mock("@/components/graph-snapshot-updates", () => ({ GraphSnapshotUpdates: () => null }));
vi.mock("@/app/graph/graph-page-client", () => ({ default: function Canvas() {
  const [owner] = useState(() => auth.session?.tenant_id);
  return <div>Evidence for {owner}</div>;
} }));
beforeEach(() => { auth.loading = false; auth.session = { tenant_id: "a", subject: "reader" }; });
it("retains a valid session during refresh and discards evidence at logout", () => {
  const view = render(<GraphSurface />);
  auth.loading = true;
  view.rerender(<GraphSurface />);
  expect(screen.getByText("Evidence for a")).toBeVisible();
  auth.session = null;
  view.rerender(<GraphSurface />);
  expect(screen.queryByText("Evidence for a")).not.toBeInTheDocument();
});
it("discards the previous tenant canvas when the authenticated owner changes", () => {
  const view = render(<GraphSurface />);
  auth.session = { tenant_id: "b", subject: "reader" };
  view.rerender(<GraphSurface />);
  expect(screen.getByText("Evidence for b")).toBeVisible();
  expect(screen.queryByText("Evidence for a")).not.toBeInTheDocument();
});
