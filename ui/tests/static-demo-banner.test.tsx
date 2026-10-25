import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { StaticDemoBanner } from "@/components/static-demo-banner";

afterEach(() => vi.unstubAllEnvs());

describe("StaticDemoBanner", () => {
  it("says the demo is read-only sample data and links the quick start", () => {
    vi.stubEnv("NEXT_PUBLIC_STATIC_DEMO", "1");
    render(<StaticDemoBanner />);
    const banner = screen.getByRole("note", { name: "Read-only demo" });
    expect(banner).toHaveTextContent("This is a read-only demo — install agent-bom to run it on your own environment.");
    expect(banner).toHaveTextContent(/sample data/i);
    expect(screen.getByRole("link", { name: /quick start/i })).toHaveAttribute(
      "href", "https://koda-ai-studio.github.io/agent-bom/getting-started/quickstart/",
    );
  });

  it("renders nothing in a normal build", () => {
    const { container } = render(<StaticDemoBanner />);
    expect(container).toBeEmptyDOMElement();
  });
});
