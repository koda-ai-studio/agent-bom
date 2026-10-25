import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AdvisoryAffectedView } from "@/components/advisories/advisory-affected-view";
import { getAdvisoryAffected, type AdvisoryAffectedResponse } from "@/lib/advisory-affected";
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
  return { ...actual, getAdvisoryAffected: vi.fn() };
});

const fetchAffected = vi.mocked(getAdvisoryAffected);
const php2shell = fixture as AdvisoryAffectedResponse;
const clone = (patch: Partial<AdvisoryAffectedResponse> = {}): AdvisoryAffectedResponse => ({ ...structuredClone(php2shell), ...patch });

beforeEach(() => {
  navState.search = "id=CVE-2026-109618";
  replaceMock.mockReset();
  fetchAffected.mockReset();
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

  it("asks for an advisory id when none is selected", async () => {
    navState.search = "";
    render(<AdvisoryAffectedView />);
    fireEvent.change(screen.getByLabelText("Advisory ID"), { target: { value: "CVE-2026-109618" } });
    fireEvent.click(screen.getByRole("button", { name: "Show affected assets" }));
    expect(replaceMock).toHaveBeenLastCalledWith("/advisories?id=CVE-2026-109618", { scroll: false });
    expect(fetchAffected).not.toHaveBeenCalled();
  });
});
