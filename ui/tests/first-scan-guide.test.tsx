import { spawnSync } from "node:child_process";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { FirstScanGuide } from "@/components/first-scan-guide";

const auth = vi.hoisted(() => ({ loading: false, hasCapability: vi.fn() }));
vi.mock("@/components/auth-provider", () => ({ useAuthState: () => auth }));

describe("first scan guidance", () => {
  beforeEach(() => { auth.loading = false; auth.hasCapability.mockReturnValue(true); });

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
    expect(screen.getByText(/agent-bom scan \. --no-discover --context-graph/)).toHaveTextContent('--push-url "${AGENT_BOM_PUSH_URL:?Set the control-plane ingestion URL}"');
    expect(screen.getByText(/AGENT_BOM_PUSH_API_KEY through your secret manager/)).toBeVisible();
    expect(screen.getByText(/including any deployment prefix/)).toBeVisible();
    expect(screen.getByRole("button", { name: "Copy project command" })).toBeVisible();
  });

  it("checks push configuration before scanning without putting the key in arguments", () => {
    render(<FirstScanGuide onImport={vi.fn()} />);
    const command = screen.getByText(/agent-bom scan \. --no-discover --context-graph/, { selector: "code" }).textContent!;
    const script = `agent-bom() { printf 'scan-started\\n'; printf '%s\\n' "$@"; test -n "$AGENT_BOM_PUSH_API_KEY"; }; ${command}`;
    const run = (extra: Record<string, string>) => spawnSync("/bin/bash", ["-c", script], {
      encoding: "utf8", env: { PATH: "/usr/bin:/bin", NODE_ENV: "test", ...extra },
    });
    const missingUrl = run({ AGENT_BOM_PUSH_API_KEY: "fixture-only" });
    expect(missingUrl.status).not.toBe(0);
    expect(missingUrl.stdout).not.toContain("scan-started");
    const missingKey = run({ AGENT_BOM_PUSH_URL: "https://control.example/v1/results/push" });
    expect(missingKey.status).not.toBe(0);
    expect(missingKey.stdout).not.toContain("scan-started");
    expect(missingKey.stderr).toContain("AGENT_BOM_PUSH_API_KEY");
    const configured = run({ AGENT_BOM_PUSH_URL: "https://control.example/v1/results/push", AGENT_BOM_PUSH_API_KEY: "fixture-only" });
    expect(configured.status).toBe(0);
    expect(configured.stdout).toContain("scan-started");
    expect(configured.stdout).not.toContain("fixture-only");
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
    expect(screen.getByText(pending ? "Checking scan access…" : /Ask an administrator for scan access/)).toBeVisible();
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
