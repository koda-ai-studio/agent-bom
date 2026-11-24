import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AdvisoryAffectedView } from "@/components/advisories/advisory-affected-view";
import { countFindingsReferencing, getAdvisoryAffected, type AdvisoryAffectedResponse } from "@/lib/advisory-affected";
import { getAffected, type AffectedAnswer } from "@/lib/incident-exposure";
import { ApiConflictError, ApiNotFoundError, ApiServerError } from "@/lib/api-errors";
import fixture from "./fixtures/php2shell-affected.json";

const { navState, replaceMock } = vi.hoisted(() => ({ navState: { search: "id=CVE-2026-109618" }, replaceMock: vi.fn() }));

vi.mock("next/navigation", () => ({
  usePathname: () => "/advisories",
  useRouter: () => ({ replace: replaceMock, push: replaceMock }),
  useSearchParams: () => new URLSearchParams(navState.search),
}));

vi.mock("@/lib/advisory-affected", async () => {
  const actual = await vi.importActual<typeof import("@/lib/advisory-affected")>("@/lib/advisory-affected");
  return { ...actual, getAdvisoryAffected: vi.fn(), countFindingsReferencing: vi.fn() };
});

vi.mock("@/lib/incident-exposure", async () => {
  const actual = await vi.importActual<typeof import("@/lib/incident-exposure")>("@/lib/incident-exposure");
  return { ...actual, getAffected: vi.fn() };
});
const fetchAffected = vi.mocked(getAdvisoryAffected);
const fetchExposure = vi.mocked(getAffected);
const exposure = (verdict: AffectedAnswer["verdict"]): AffectedAnswer => ({
  tenant_id: "t", query: { raw: "q", kind: "advisory", advisory: "CVE-2026-109618" }, verdict,
  verdict_basis: verdict === "not_found" ? [] : ["findings"],
  inventory: { available: true, affected: 1, possibly_affected: 0, not_affected: 0, assets_examined: 2 },
  findings: { total: 2, open: 1, resolved: 1, suppressed: 0, severity: { high: 2 }, kev: true, fix_available: 1, no_fix: 1, internet_exposed: 0, advisories: ["CVE-2026-109618"], packages: ["pillow@9.0.0"] },
  exposure: { first_seen: "2026-08-01T00:00:00Z", last_seen: "2026-09-01T00:00:00Z", still_open: true, last_resolved_at: null },
  assets: [], assets_truncated: false, findings_truncated: false, findings_href: "/findings?q=CVE-2026-109618&status=all",
  reach: { by_kind: { credentials: 2, data_stores: 1 }, items: {}, agents_on_findings: [], servers_on_findings: [], basis: "graph_snapshot", scan_id: "snap-1", advisories_walked: [] },
} as AffectedAnswer);
const countReferencing = vi.mocked(countFindingsReferencing);
const php2shell = fixture as AdvisoryAffectedResponse;
const clone = (patch: Partial<AdvisoryAffectedResponse> = {}): AdvisoryAffectedResponse => ({ ...structuredClone(php2shell), ...patch });

beforeEach(() => {
  navState.search = "id=CVE-2026-109618";
  replaceMock.mockReset();
  fetchAffected.mockReset();
  countReferencing.mockReset();
  countReferencing.mockResolvedValue(0);
  fetchExposure.mockReset();
  fetchExposure.mockResolvedValue(exposure("affected"));
});

function rowFor(label: string) {
  const table = screen.getByRole("table", { name: "Affected assets" });
  return within(table).getAllByRole("row").find(row => row.textContent?.includes(label))!;
}

describe("advisory affected assets", () => {
  it("renders the PHP2Shell answer per asset with summary tiles, verdicts, patch targets and graph links", async () => {
    fetchAffected.mockResolvedValue(clone());
    render(<AdvisoryAffectedView />);

    await screen.findByRole("table", { name: "Affected assets" });
    expect(fetchAffected).toHaveBeenCalledWith("CVE-2026-109618", { verdict: "all", q: "", cursor: null, limit: 50 }, expect.any(AbortSignal));
    const tiles = screen.getByRole("list", { name: "Verdict summary" });
    const tileText = within(tiles).getAllByRole("listitem").map(tile => tile.textContent);
    expect(tileText).toEqual(["1Affected", "1Possibly affected (distro)", "1Not affected", "1Clean scanned"]);
    expect(screen.getByText(/3 assets · 3 scan reports examined/)).toBeInTheDocument();
    expect(screen.getByText("CVE-2026-109618")).toBeInTheDocument();
    expect(screen.getByText(/Operator advisory/, { selector: "[data-testid=advisory-source]" })).toBeInTheDocument();

    const affected = rowFor("php:8.3.30-cli");
    expect(within(affected).getByTestId("verdict-badge")).toHaveTextContent("Affected");
    expect(within(affected).getByTestId("verdict-badge")).toHaveAttribute("data-verdict", "affected");
    expect(within(affected).getByTestId("patch-target")).toHaveTextContent("8.3.36");
    expect(within(affected).getByText("Operator advisory")).toBeInTheDocument();
    expect(within(affected).getByRole("link", { name: "Blast radius for php 8.3.30 on php:8.3.30-cli" }))
      .toHaveAttribute("href", "/security-graph?lens=attack-path&scan=scan-php-8.3.30&node=pkg%3Ageneric%3Aphp%408.3.30");

    const distro = rowFor("abtest/php-debian:12");
    const badge = within(distro).getByTestId("verdict-badge");
    expect(badge).toHaveTextContent("Possibly affected — verify distro advisory");
    expect(badge).toHaveAttribute("data-verdict", "possibly_affected");
    expect(badge.className).not.toMatch(/critical|danger/);
    expect(within(distro).getByText(/distro package php8\.2-cli 8\.2\.29-1~deb12u1 ships php; verify against the distribution's advisory/)).toBeInTheDocument();
    expect(within(distro).getByTestId("patch-target")).toHaveTextContent("verify distro advisory");

    const clean = rowFor("php:8.3.36-cli");
    expect(within(clean).getByTestId("verdict-badge")).toHaveTextContent("Not affected");
    expect(within(clean).getByTestId("patch-target")).toHaveTextContent("Not needed");
    expect(screen.queryByText(/incomplete/i)).toBeNull();
    expect(screen.queryByText(/\bsafe\b/i)).toBeNull();
  });

  it("keeps summary tiles from the response, not from the visible page", async () => {
    const response = clone({ rows: [php2shell.rows[1]!], count: 1 });
    response.summary = { ...response.summary, possibly_affected: 7, affected: 42 };
    navState.search = "id=CVE-2026-109618&verdict=possibly_affected";
    fetchAffected.mockResolvedValue(response);
    render(<AdvisoryAffectedView />);
    const tiles = await screen.findByRole("list", { name: "Verdict summary" });
    expect(within(tiles).getAllByRole("listitem")[0]).toHaveTextContent("42Affected");
    expect(within(tiles).getAllByRole("listitem")[1]).toHaveTextContent("7Possibly affected (distro)");
    expect(fetchAffected.mock.calls[0]![1]).toMatchObject({ verdict: "possibly_affected" });
    expect(screen.getByRole("button", { name: /Possibly affected/, pressed: true })).toBeInTheDocument();
  });

  it("syncs verdict pills and search to the URL", async () => {
    fetchAffected.mockResolvedValue(clone());
    render(<AdvisoryAffectedView />);
    await screen.findByRole("table", { name: "Affected assets" });
    fireEvent.click(screen.getByRole("button", { name: /^Affected/ }));
    expect(replaceMock).toHaveBeenLastCalledWith("/advisories?id=CVE-2026-109618&verdict=affected", { scroll: false });
    fireEvent.change(screen.getByRole("searchbox", { name: "Search asset or package" }), { target: { value: "php8.2" } });
    fireEvent.submit(screen.getByRole("search"));
    expect(replaceMock).toHaveBeenLastCalledWith("/advisories?id=CVE-2026-109618&q=php8.2", { scroll: false });
  });

  it("pages with the opaque cursor and offers a reload when the snapshot changed (409)", async () => {
    fetchAffected
      .mockResolvedValueOnce(clone({ rows: php2shell.rows.slice(0, 2), count: 2, has_more: true, next_cursor: "cur-2", limit: 2 }))
      .mockRejectedValueOnce(new ApiConflictError("snapshot changed", { status: 409, statusText: "Conflict", url: "", method: "GET" }))
      .mockResolvedValueOnce(clone());
    render(<AdvisoryAffectedView />);
    await screen.findByRole("table", { name: "Affected assets" });
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(await screen.findByText("Results changed — reload from first page")).toBeInTheDocument();
    expect(fetchAffected.mock.calls[1]![1]).toMatchObject({ cursor: "cur-2" });
    fireEvent.click(screen.getByRole("button", { name: "Reload from first page" }));
    await waitFor(() => expect(fetchAffected).toHaveBeenCalledTimes(3));
    expect(fetchAffected.mock.calls[2]![1]).toMatchObject({ cursor: null });
    expect(await screen.findByRole("table", { name: "Affected assets" })).toBeInTheDocument();
    expect(screen.queryByText("Results changed — reload from first page")).toBeNull();
  });

  it("shows incomplete answers honestly and words zero affected as not found in what was scanned", async () => {
    const response = clone({ complete: false, rows: [php2shell.rows[2]!], count: 1, warnings: ["2 packages had versions the comparator could not order"] });
    response.summary = { ...response.summary, affected: 0, possibly_affected: 0 };
    fetchAffected.mockResolvedValue(response);
    render(<AdvisoryAffectedView />);
    expect(await screen.findByText("Incomplete — some packages could not be decided")).toBeInTheDocument();
    expect(screen.getByText("2 packages had versions the comparator could not order")).toBeInTheDocument();
    expect(screen.getByText(/Not found in what was scanned/)).toBeInTheDocument();
    expect(screen.queryByText(/\bsafe\b/i)).toBeNull();
  });

  it("names an unknown advisory and the seeding control plane instead of an empty table", async () => {
    fetchAffected.mockRejectedValueOnce(new ApiNotFoundError("Advisory not found", { status: 404, statusText: "Not Found", url: "", method: "GET" }));
    const { unmount } = render(<AdvisoryAffectedView />);
    expect(await screen.findByText("Advisory not found")).toBeInTheDocument();
    expect(screen.queryByRole("table")).toBeNull();
    unmount();

    fetchAffected.mockRejectedValueOnce(new ApiServerError("seeding", { status: 503, statusText: "Service Unavailable", url: "", method: "GET" }, 30));
    render(<AdvisoryAffectedView />);
    expect(await screen.findByText("Control plane is still loading inventory")).toBeInTheDocument();
    expect(screen.getByText(/Retry in about 30 seconds/)).toBeInTheDocument();
  });

  it("links an unknown advisory to the stored findings that reference it", async () => {
    navState.search = "id=CVE-2023-4863";
    countReferencing.mockResolvedValue(50);
    fetchAffected.mockRejectedValueOnce(new ApiNotFoundError("Advisory not found", { status: 404, statusText: "Not Found", url: "", method: "GET" }));
    render(<AdvisoryAffectedView />);
    expect(await screen.findByText("50 findings reference CVE-2023-4863")).toBeInTheDocument();
    expect(countReferencing).toHaveBeenCalledWith("CVE-2023-4863", expect.any(AbortSignal));
    expect(screen.getByRole("link", { name: "View in Findings" })).toHaveAttribute("href", "/findings?q=CVE-2023-4863");
  });

  it("labels an answer built from stored findings and says why it is incomplete", async () => {
    const response = clone({ complete: false, warnings: [], incomplete_reason: "no advisory feed record; answered from stored findings" });
    response.advisory = { ...response.advisory, source: "scan" };
    fetchAffected.mockResolvedValue(response);
    render(<AdvisoryAffectedView />);
    expect(await screen.findByText("From stored findings", { selector: "[data-testid=advisory-source]" })).toBeInTheDocument();
    expect(screen.getByText("Incomplete — answered from stored findings")).toBeInTheDocument();
    expect(screen.getByText(/no advisory feed record; answered from stored findings/i)).toBeInTheDocument();
  });

  it("leads with the exposure answer: verdict, window, findings and reach", async () => {
    navState.search = "id=CVE-2026-109618";
    fetchAffected.mockResolvedValue(clone());
    render(<AdvisoryAffectedView />);
    const panel = await screen.findByTestId("exposure-panel");
    expect(panel).toHaveTextContent("Affected");
    expect(panel).toHaveTextContent("2026-08-01 → now");
    expect(panel).toHaveTextContent("1 open · 1 resolved · KEV");
    expect(screen.getByTestId("exposure-reach")).toHaveTextContent("2 credentials · 1 data stores");
    expect(fetchExposure).toHaveBeenCalledWith("CVE-2026-109618", expect.anything());
  });

  it("answers a package with findings and reach alone, never an advisory lookup", async () => {
    navState.search = "id=pillow%409.0.0";
    render(<AdvisoryAffectedView />);
    expect(await screen.findByTestId("exposure-panel")).toBeInTheDocument();
    expect(fetchExposure).toHaveBeenCalledWith("pillow@9.0.0", expect.anything());
    expect(fetchAffected).not.toHaveBeenCalled();
  });

  it("asks for an advisory id when none is selected", async () => {
    navState.search = "";
    render(<AdvisoryAffectedView />);
    fireEvent.change(screen.getByLabelText("Advisory ID or package"), { target: { value: "CVE-2026-109618" } });
    fireEvent.click(screen.getByRole("button", { name: "Show affected assets" }));
    expect(replaceMock).toHaveBeenLastCalledWith("/advisories?id=CVE-2026-109618", { scroll: false });
    expect(fetchAffected).not.toHaveBeenCalled();
  });
});

describe("exposure panel resilience", () => {
  it("reads an unexpected body as unavailable instead of breaking the page", async () => {
    navState.search = "id=pillow";
    fetchExposure.mockResolvedValue({ detail: "Not Found" } as unknown as AffectedAnswer);
    render(<AdvisoryAffectedView />);
    expect(await screen.findByText("Exposure for pillow is unavailable right now.")).toBeInTheDocument();
  });
});
