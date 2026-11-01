import { describe, expect, it } from "vitest";
import type { AuthMeResponse } from "@/lib/api";
import { sessionPresentation } from "@/lib/session-presentation";

const anonymous = { auth_method: "anonymous", auth_required: false, authenticated: true, subject: "anonymous" } as unknown as AuthMeResponse;

describe("session chip reflects the deployment mode", () => {
  it("names an anonymous reader of the seeded demo estate a demo visitor", () => {
    const view = sessionPresentation(anonymous, { demoEstate: true });
    expect(view.name).toBe("Demo visitor");
    expect(view.method).toBe("Read-only demo");
    expect(view.canSignOut).toBe(false);
  });
  it("keeps the unauthenticated warning for a no-auth deployment that is not a demo", () => {
    const view = sessionPresentation(anonymous, { demoEstate: false });
    expect(view.name).toBe("Unauthenticated access");
    expect(view.method).toBe("Authentication disabled");
  });
  it("never relabels a signed-in principal as a demo visitor", () => {
    const signedIn = { auth_method: "oidc", auth_required: true, authenticated: true, subject: "ops@example.test" } as unknown as AuthMeResponse;
    expect(sessionPresentation(signedIn, { demoEstate: true }).name).toBe("ops@example.test");
  });
});
