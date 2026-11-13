import { createElement } from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import RegistryPage from "@/app/registry/page";

const { apiMock, navigationMock } = vi.hoisted(() => ({
  apiMock: { listRegistry: vi.fn(), getRegistryServer: vi.fn() },
  navigationMock: { query: "" },
}));

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(navigationMock.query),
  useRouter: () => ({ replace: vi.fn(), push: vi.fn() }),
  usePathname: () => "/registry",
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return { ...actual, api: apiMock };
});

function server(i: number, risk: string) {
  return {
    id: `pub/server-${i}`, name: `server-${i}`, publisher: "pub", verified: false, transport: "stdio", risk_level: risk,
    packages: [], source_url: "", description: null, sigstore_bundle: null, tools: [], credential_env_vars: [], category: "dev",
    license: null, latest_version: null, known_cves: [], command_patterns: [], risk_justification: null,
  };
}

function page(params: { offset?: number; risk?: string[] } = {}) {
  const risk = params.risk?.[0];
  const total = risk === "high" ? 3 : 60;
  const offset = params.offset ?? 0;
  const rows = Array.from({ length: Math.min(25, total - offset) }, (_, i) => server(offset + i, risk ?? "low"));
  return {
    servers: rows, count: 1320, total, limit: 25, offset, has_more: offset + 25 < total,
    next_cursor: offset + 25 < total ? String(offset + 25) : null,
    facets: { risk_level: { unknown: 50, high: 3, low: 7 }, category: { dev: 60 } },
    risk_counts: { unknown: 1208, medium: 51, high: 40, low: 21 },
    meta: { updated: null, total_servers: 1320, sources: [], source_url: null, schema_version: null },
  };
}

beforeEach(() => {
  navigationMock.query = "";
  apiMock.listRegistry.mockReset();
  apiMock.listRegistry.mockImplementation(async (params?: { offset?: number; risk?: string[] }) => page(params));
});

describe("MCP catalog pagination", () => {
  it("asks the server for one 25-row page and shows catalog totals from the server", async () => {
    render(createElement(RegistryPage));

    await waitFor(() => expect(screen.getByText("Page 1 of 3 (60 servers)")).toBeInTheDocument());
    expect(apiMock.listRegistry).toHaveBeenCalledWith(expect.objectContaining({ limit: 25, offset: 0 }), expect.any(AbortSignal));
    expect(screen.getByText(/1,320 known servers .* 40 high · 51 medium/)).toBeInTheDocument();
    expect(screen.getAllByText(/^server-\d+$/).length).toBe(25);
  });

  it("pages, filters by risk and searches on the server", async () => {
    render(createElement(RegistryPage));
    await waitFor(() => expect(screen.getByText("Page 1 of 3 (60 servers)")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: /Next/ }));
    await waitFor(() =>
      expect(apiMock.listRegistry).toHaveBeenLastCalledWith(expect.objectContaining({ offset: 25 }), expect.any(AbortSignal)),
    );

    fireEvent.click(screen.getByRole("button", { name: /^High/ }));
    await waitFor(() => expect(screen.getByText("Page 1 of 1 (3 servers)")).toBeInTheDocument());
    expect(apiMock.listRegistry).toHaveBeenLastCalledWith(expect.objectContaining({ risk: ["high"], offset: 0 }), expect.any(AbortSignal));

    fireEvent.change(screen.getByPlaceholderText("Search servers, publishers, categories..."), { target: { value: "github" } });
    await waitFor(() =>
      expect(apiMock.listRegistry).toHaveBeenLastCalledWith(expect.objectContaining({ q: "github" }), expect.any(AbortSignal)),
    );
  });
});
