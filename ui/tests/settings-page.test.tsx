import { render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import SettingsPage from "@/app/settings/page";
const state = vi.hoisted(() => ({ session: { authenticated: true, auth_required: true, auth_method: "browser_session", subject: "automation-key", tenant_id: "staging", role: "viewer", role_summary: { display_name: "Viewer" } }, hasCapability: vi.fn(() => false), signOut: vi.fn() }));
vi.mock("@/components/auth-provider", () => ({ useAuthState: () => state }));
vi.mock("next/link", () => ({ default: ({ href, children }: { href: string; children: React.ReactNode }) => <a href={href}>{children}</a> }));
afterEach(() => vi.clearAllMocks());
it("gives a viewer truthful identity and appearance without admin links or unsupported scope switching", () => {
  render(<SettingsPage />);
  expect(screen.getByText("automation-key")).toBeInTheDocument();
  expect(screen.getByText("staging")).toBeInTheDocument();
  expect(screen.getByText(/identity belongs to an API key/)).toBeInTheDocument();
  expect(screen.queryByRole("link", { name: /Access.*keys/ })).not.toBeInTheDocument();
  expect(screen.queryByRole("link", { name: /Control plane security/ })).not.toBeInTheDocument();
  expect(screen.queryByRole("combobox")).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "System" })).toBeInTheDocument();
});
