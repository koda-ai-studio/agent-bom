import { afterEach, describe, expect, it, vi } from "vitest";

import { sessionPresentation } from "@/lib/session-presentation";

afterEach(() => vi.unstubAllEnvs());

const anonymous = { authenticated: true, auth_required: false, auth_method: "anonymous" } as never;

describe("session presentation in the read-only demo", () => {
  it("names the viewer a demo visitor, not unauthenticated access", () => {
    vi.stubEnv("NEXT_PUBLIC_STATIC_DEMO", "1");
    const shown = sessionPresentation(anonymous);
    expect(shown.name).toBe("Demo visitor");
    expect(shown.method).toBe("Read-only demo");
    expect(shown.description).toMatch(/sample data/);
    expect(shown.canSignOut).toBe(false);
  });

  it("keeps the honest label outside the demo", () => {
    expect(sessionPresentation(anonymous).name).toBe("Unauthenticated access");
  });
});
