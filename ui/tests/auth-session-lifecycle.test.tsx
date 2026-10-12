import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuthProvider, useAuthState } from "@/components/auth-provider";
import { api, type AuthMeResponse } from "@/lib/api";
import { cachedGet, _cacheSizeForTests } from "@/lib/api-cache";

import { setExplicitlySignedOut } from "@/lib/session-intent";

const session = { authenticated: true, auth_required: true, subject: "operator", tenant_id: "alpha", role_summary: { capabilities: ["inventory.read"] } } as AuthMeResponse;
function Probe() {
  const auth = useAuthState();
  return <><div>{auth.session?.subject ?? "signed out"}</div><button onClick={() => void auth.refresh()}>Refresh</button><button onClick={() => void auth.signOut()}>Sign out</button></>;
}
beforeEach(() => { localStorage.clear(); vi.spyOn(api, "getAuthMe").mockResolvedValue(session); vi.spyOn(api, "deleteAuthSession").mockResolvedValue(); });
afterEach(() => { localStorage.clear(); vi.restoreAllMocks(); setExplicitlySignedOut(false); });

it("locks content immediately, clears cached evidence, and ignores an older auth response after logout", async () => {
  render(<AuthProvider><Probe /></AuthProvider>);
  await screen.findByText("operator");
  let resolve!: (value: AuthMeResponse) => void;
  vi.mocked(api.getAuthMe).mockReturnValueOnce(new Promise(r => { resolve = r; }));
  await cachedGet("private", async () => ({ tenant: "alpha" }));
  fireEvent.click(screen.getByText("Refresh"));
  fireEvent.click(screen.getByText("Sign out"));
  await waitFor(() => expect(api.deleteAuthSession).toHaveBeenCalledOnce());
  await act(async () => resolve(session));
  expect(screen.queryByText("operator")).not.toBeInTheDocument();
  expect(_cacheSizeForTests().entries).toBe(0);
});

it("does not probe or automatically recreate sessions after explicit logout and remount", async () => {
  const view = render(<AuthProvider><Probe /></AuthProvider>);
  await screen.findByText("operator");
  fireEvent.click(screen.getByText("Sign out"));
  await waitFor(() => expect(api.deleteAuthSession).toHaveBeenCalledOnce());
  view.unmount();
  vi.mocked(api.getAuthMe).mockClear();
  render(<AuthProvider><Probe /></AuthProvider>);
  fireEvent.click(screen.getByText("Refresh"));
  await act(async () => {});
  expect(api.getAuthMe).not.toHaveBeenCalled();
});

it("keeps the browser locked but reports failure when revocation cannot be confirmed", async () => {
  vi.mocked(api.deleteAuthSession).mockRejectedValue(new Error("internal secret"));
  function FailureProbe() { const auth = useAuthState(); return <><Probe /><p>{auth.signOutError}</p></>; }
  render(<AuthProvider><FailureProbe /></AuthProvider>);
  await screen.findByText("operator");
  fireEvent.click(screen.getByText("Sign out"));
  await screen.findByText(/Sign-out could not be confirmed/);
  expect(screen.queryByText("operator")).not.toBeInTheDocument();
  expect(screen.queryByText(/internal secret/)).not.toBeInTheDocument();
});

it("locks another tab on sign-out notification and unmounts session-scoped content", async () => {
  render(<AuthProvider><Probe /></AuthProvider>);
  await screen.findByText("operator");
  await act(async () => {
    localStorage.setItem("agent-bom-signed-out", "1");
    window.dispatchEvent(new StorageEvent("storage", { key: "agent-bom-signed-out", newValue: "1" }));
  });
  expect(screen.queryByText("operator")).not.toBeInTheDocument();
  expect(api.deleteAuthSession).not.toHaveBeenCalled();
});

it("does not claim confirmed revocation after reloading a failed sign-out", async () => {
  vi.mocked(api.deleteAuthSession).mockRejectedValue(new Error("unavailable"));
  const view = render(<AuthProvider><Probe /></AuthProvider>);
  await screen.findByText("operator");
  fireEvent.click(screen.getByText("Sign out"));
  await waitFor(() => expect(api.deleteAuthSession).toHaveBeenCalledOnce());
  view.unmount();
  function ConfirmationProbe() { const auth = useAuthState(); return <p>{auth.signOutConfirmed ? "confirmed" : "unconfirmed"}</p>; }
  render(<AuthProvider><ConfirmationProbe /></AuthProvider>);
  await screen.findByText("unconfirmed");
  expect(screen.queryByText("confirmed")).not.toBeInTheDocument();
});

it("preserves sign-out intent when storage reads succeed but writes fail", async () => {
  vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new DOMException("Quota exceeded"); });
  render(<AuthProvider><Probe /></AuthProvider>);
  await screen.findByText("operator");
  fireEvent.click(screen.getByText("Sign out"));
  await waitFor(() => expect(api.deleteAuthSession).toHaveBeenCalledOnce());
  fireEvent.click(screen.getByText("Refresh"));
  await act(async () => {});
  expect(screen.queryByText("operator")).not.toBeInTheDocument();
});

it("honors the server sign-out marker after browser storage was lost", async () => {
  const { ApiAuthError, ApiConflictError } = await import("@/lib/api-errors");
  vi.mocked(api.getAuthMe).mockRejectedValue(new ApiAuthError("Unauthorized", { status: 401, statusText: "Unauthorized", method: "GET", url: "/v1/auth/me" }));
  const exchange = vi.spyOn(api, "createDevAuthSession").mockRejectedValue(new ApiConflictError("Explicit sign-in required", { status: 409, statusText: "Conflict", method: "POST", url: "/v1/auth/dev-session" }));
  function ResumeProbe() { const auth = useAuthState(); return <><p>{auth.signedOut ? "locked by intent" : "not locked"}</p><button onClick={() => void auth.resumeSession()}>Resume</button></>; }
  render(<AuthProvider><ResumeProbe /></AuthProvider>);
  await screen.findByText("locked by intent");
  fireEvent.click(screen.getByText("Resume"));
  await waitFor(() => expect(exchange).toHaveBeenLastCalledWith(true));
});
