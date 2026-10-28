import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.resetModules();
});

function manifest(routes: string[]) {
  return vi.fn(async () => new Response(JSON.stringify({ schema_version: "static-demo-routes.v1", routes }), { status: 200 }));
}

describe("ViewAllFrameworksLink", () => {
  it("links to the compliance page outside the static demo", async () => {
    const { ViewAllFrameworksLink } = await import("@/components/overview/compliance-link");
    render(<ViewAllFrameworksLink />);
    expect(screen.getByRole("link", { name: "View all frameworks" })).toHaveAttribute("href", "/compliance");
  });

  it("is omitted in the static demo when the compliance page has no sample data, so the link is never a dead end", async () => {
    vi.stubEnv("NEXT_PUBLIC_STATIC_DEMO", "1");
    vi.stubGlobal("fetch", manifest(["/", "/findings"]));
    const { ViewAllFrameworksLink } = await import("@/components/overview/compliance-link");
    render(<ViewAllFrameworksLink />);
    await waitFor(() => expect(screen.getByTestId("view-all-frameworks-unavailable")).toBeInTheDocument());
    expect(screen.queryByRole("link", { name: "View all frameworks" })).toBeNull();
  });

  it("keeps the link in the static demo once the compliance page is recorded", async () => {
    vi.stubEnv("NEXT_PUBLIC_STATIC_DEMO", "1");
    vi.stubGlobal("fetch", manifest(["/", "/compliance"]));
    const { ViewAllFrameworksLink } = await import("@/components/overview/compliance-link");
    render(<ViewAllFrameworksLink />);
    await waitFor(() => expect(screen.getByRole("link", { name: "View all frameworks" })).toBeInTheDocument());
  });
});
