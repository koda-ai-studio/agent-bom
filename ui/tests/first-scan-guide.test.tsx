import { spawnSync } from "node:child_process";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { FirstScanGuide } from "@/components/first-scan-guide";

const auth = vi.hoisted(() => ({ loading: false, hasCapability: vi.fn(), session: { auth_required: true } as Record<string, unknown> | null }));
vi.mock("@/components/auth-provider", () => ({ useAuthState: () => auth }));
const PUSH_URL = "http://localhost:3000/v1/results/push";

describe("first scan guidance", () => {
  beforeEach(() => { auth.loading = false; auth.hasCapability.mockReturnValue(true); auth.session = { auth_required: true }; });

  it("offers distinct source paths and explains the retained evidence workflow", () => {
    render(<FirstScanGuide onImport={vi.fn()} />);
    expect(screen.getByRole("link", { name: "Connect a source" })).toHaveAttribute("href", "/connections?tab=connect");
    expect(screen.getByRole("heading", { name: "Send a local project" })).toBeVisible();
    expect(screen.getByRole("list", { name: "Your first investigation" })).toHaveTextContent("Review inventory");
    expect(screen.getByRole("list", { name: "Your first investigation" })).toHaveTextContent("Understand impact");
    expect(screen.getByRole("list", { name: "Your first investigation" })).toHaveTextContent("Fix and verify");
  });

  it("keeps the local project command explicit, scoped and credential-free", () => {
    render(<FirstScanGuide onImport={vi.fn()} />);
    fireEvent.click(screen.getByText("Show project command"));
    expect(screen.getByText(/agent-bom scan \. --no-discover --context-graph/)).toHaveTextContent(`--push-url "\${AGENT_BOM_PUSH_URL:-${PUSH_URL}}"`);
    expect(screen.getByText(/AGENT_BOM_PUSH_API_KEY through your secret manager/)).toBeVisible();
    expect(screen.getByText(PUSH_URL, { selector: "code:not(.block)" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Copy project command" })).toBeVisible();
    expect(screen.getByRole("link", { name: "Create an API key" })).toHaveAttribute("href", "/audit");
    // Never CLI-only: the in-product equivalent sits beside the snippet.
    expect(screen.getByRole("link", { name: "Scan from this control plane instead" })).toHaveAttribute("href", "/scan");
  });

  it("checks push configuration before scanning without putting the key in arguments", () => {
    render(<FirstScanGuide onImport={vi.fn()} />);
    const command = screen.getByText(/agent-bom scan \. --no-discover --context-graph/, { selector: "code" }).textContent!;
    const script = `agent-bom() { printf 'scan-started\\n'; printf '%s\\n' "$@"; test -n "$AGENT_BOM_PUSH_API_KEY"; }; ${command}`;
    const run = (extra: Record<string, string>) => spawnSync("/bin/bash", ["-c", script], {
      encoding: "utf8", env: { PATH: "/usr/bin:/bin", NODE_ENV: "test", ...extra },
    });
    // The deployment URL is pre-filled, so only the key can stop the run.
    const defaultUrl = run({ AGENT_BOM_PUSH_API_KEY: "fixture-only" });
    expect(defaultUrl.status).toBe(0);
    expect(defaultUrl.stdout).toContain(PUSH_URL);
    const missingKey = run({ AGENT_BOM_PUSH_URL: "https://control.example/v1/results/push" });
    expect(missingKey.status).not.toBe(0);
    expect(missingKey.stdout).not.toContain("scan-started");
    expect(missingKey.stderr).toContain("AGENT_BOM_PUSH_API_KEY");
    const configured = run({ AGENT_BOM_PUSH_URL: "https://control.example/v1/results/push", AGENT_BOM_PUSH_API_KEY: "fixture-only" });
    expect(configured.status).toBe(0);
    expect(configured.stdout).toContain("scan-started");
    expect(configured.stdout).toContain("https://control.example/v1/results/push");
    expect(configured.stdout).not.toContain("fixture-only");
  });

  it("tells an anonymous no-auth viewer the truth instead of asking an administrator", () => {
    auth.session = { auth_required: false, auth_method: "anonymous" };
    auth.hasCapability.mockReturnValue(false);
    render(<FirstScanGuide onImport={vi.fn()} />);
    expect(screen.queryByText(/Ask an administrator/)).not.toBeInTheDocument();
    expect(screen.getByText(/anonymous access is read-only/i)).toBeVisible();
    fireEvent.click(screen.getByText("Show project command"));
    expect(screen.getByText(/requires an API key with push permission issued by the operator/i)).toBeVisible();
    expect(screen.queryByRole("link", { name: "Create an API key" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Preview a report in this browser instead" })).toBeVisible();
  });

  it("omits the API-key step when the session can push without one", () => {
    auth.session = { auth_required: false, auth_method: "anonymous" };
    auth.hasCapability.mockReturnValue(true);
    render(<FirstScanGuide onImport={vi.fn()} />);
    fireEvent.click(screen.getByText("Show project command"));
    const command = screen.getByText(/agent-bom scan \. --no-discover --context-graph/, { selector: "code" }).textContent!;
    expect(command).not.toContain("AGENT_BOM_PUSH_API_KEY");
    expect(command).toContain(PUSH_URL);
    expect(screen.queryByText(/through your secret manager/)).not.toBeInTheDocument();
  });

  it("asks a signed-in user without key management to request a push key", () => {
    auth.hasCapability.mockImplementation((cap: string) => cap === "scan.run");
    render(<FirstScanGuide onImport={vi.fn()} />);
    fireEvent.click(screen.getByText("Show project command"));
    expect(screen.getByText(/Ask an administrator for an API key with push permission/)).toBeVisible();
    expect(screen.queryByRole("link", { name: "Create an API key" })).not.toBeInTheDocument();
  });

  it("links permitted operators to explicit scan targets", () => {
    render(<FirstScanGuide onImport={vi.fn()} />);
    expect(screen.getByRole("link", { name: "Choose a scan target" })).toHaveAttribute("href", "/scan");
    expect(auth.hasCapability).toHaveBeenCalledWith("scan.run");
    fireEvent.click(screen.getByText("Preview a saved or sample report"));
    expect(screen.getByText(/does not upload it to the control plane/)).toBeVisible();
  });

  it.each([true, false])("withholds scan actions while access is pending or denied (%s)", (pending) => {
    auth.loading = pending;
    auth.hasCapability.mockReturnValue(false);
    render(<FirstScanGuide onImport={vi.fn()} />);
    expect(screen.queryByRole("link", { name: "Choose a scan target" })).not.toBeInTheDocument();
    expect(screen.getByText(pending ? "Checking scan access…" : /Your role cannot start scans here/)).toBeVisible();
  });

  it("previews a validated local report without a network write", async () => {
    const onImport = vi.fn();
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    render(<FirstScanGuide onImport={onImport} />);
    fireEvent.click(screen.getByText("Preview a saved or sample report"));
    const report = { agents: [], blast_radius: [], scan_timestamp: "2026-09-29T00:00:00Z" };
    fireEvent.change(screen.getByLabelText("Choose report.json"), { target: { files: [new File([JSON.stringify(report)], "report.json", { type: "application/json" })] } });
    await waitFor(() => expect(onImport).toHaveBeenCalledWith(report));
    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
  });

  it("rejects an invalid report before handing it to the dashboard", async () => {
    const onImport = vi.fn();
    render(<FirstScanGuide onImport={onImport} />);
    fireEvent.click(screen.getByText("Preview a saved or sample report"));
    fireEvent.change(screen.getByLabelText("Choose report.json"), { target: { files: [new File(["not json"], "report.json")] } });
    await waitFor(() => expect(screen.getByRole("alert")).toBeVisible());
    expect(onImport).not.toHaveBeenCalled();
  });
});
