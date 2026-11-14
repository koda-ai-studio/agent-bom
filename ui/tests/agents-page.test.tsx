import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import AgentsPage from "@/app/agents/page";

const { apiMock, deploymentMock, navigationMock } = vi.hoisted(() => ({
  apiMock: {
    listAgents: vi.fn(),
    getAgentDetail: vi.fn(),
  },
  deploymentMock: { counts: undefined as unknown },
  navigationMock: { query: "" },
}));

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(navigationMock.query),
  useRouter: () => ({ replace: vi.fn(), push: vi.fn() }),
  usePathname: () => "/agents",
}));

vi.mock("next/link", () => ({
  default: ({
    href,
    children,
    title,
    className,
    onClick,
  }: {
    href: string;
    children: React.ReactNode;
    title?: string;
    className?: string;
    onClick?: (e: React.MouseEvent) => void;
  }) => (
    <a href={href} title={title} className={className} onClick={onClick}>
      {children}
    </a>
  ),
}));

vi.mock("@/hooks/use-deployment-context", () => ({
  useDeploymentContext: () => ({ counts: deploymentMock.counts }),
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return { ...actual, api: apiMock };
});

const AGENTS = [
  {
    name: "Cursor",
    agent_type: "ide",
    agent_class: "client",
    source: "config",
    config_path: "/home/u/.cursor/mcp.json",
    status: "configured",
    mcp_servers: [
      {
        name: "github",
        transport: "stdio",
        command: "npx github-mcp",
        args: [],
        packages: [
          { name: "left-pad", version: "1.0.0", ecosystem: "npm" },
          { name: "requests", version: "2.0.0", ecosystem: "pypi" },
        ],
        tools: [{ name: "create_issue" }, { name: "list_repos" }],
        credential_env_vars: ["GITHUB_TOKEN"],
        env: { GITHUB_TOKEN: "x" },
        security_blocked: false,
      },
    ],
  },
  {
    name: "ClaudeDesktop",
    agent_type: "desktop",
    agent_class: "client",
    source: "config",
    config_path: "/home/u/.claude/config.json",
    status: "configured",
    mcp_servers: [
      {
        name: "filesystem",
        transport: "sse",
        url: "https://mcp.example.com/fs",
        packages: [],
        tools: [],
        credential_env_vars: [],
        env: {},
        security_blocked: true,
      },
    ],
  },
  {
    name: "SomeBinary",
    agent_type: "cli",
    status: "installed-not-configured",
    config_path: "/usr/local/bin/somebinary",
    mcp_servers: [],
  },
];

type Row = Record<string, unknown> & { name: string; agent_type: string; status: string; source?: string };
type ListParams = { limit?: number; offset?: number; q?: string; type?: string[]; status?: string[]; source?: string[]; sort?: string | null; order?: string };

/** A stand-in for GET /v1/agents: filters, sorts and pages exactly where the server does. */
function pagingServer(rows: Row[], extra: Record<string, unknown> = {}) {
  return async (params?: ListParams) => {
    const q = (params?.q ?? "").toLowerCase();
    const facet = (row: Row, key: "type" | "status" | "source") =>
      String((key === "type" ? row.agent_type : row[key]) ?? "unknown").toLowerCase();
    const passes = (row: Row, skip?: string) =>
      (["type", "status", "source"] as const).every((key) => key === skip || !(params?.[key]?.length) || params[key]!.includes(facet(row, key)));
    const searched = rows.filter((row) => !q || [row.name, row.agent_type, row.source].some((v) => String(v ?? "").toLowerCase().includes(q)));
    let matched = searched.filter((row) => passes(row));
    if (params?.sort === "name") {
      matched = [...matched].sort((a, b) => a.name.localeCompare(b.name) * (params.order === "desc" ? -1 : 1));
    }
    const offset = params?.offset ?? 0;
    const limit = params?.limit ?? matched.length;
    const facets = Object.fromEntries((["type", "status", "source"] as const).map((key) => {
      const counts: Record<string, number> = {};
      for (const row of searched.filter((r) => passes(r, key))) counts[facet(row, key)] = (counts[facet(row, key)] ?? 0) + 1;
      return [key, counts];
    }));
    return {
      scope: "local_discovery",
      agents: matched.slice(offset, offset + limit),
      count: rows.length,
      total: matched.length,
      limit,
      offset,
      has_more: offset + limit < matched.length,
      next_cursor: offset + limit < matched.length ? String(offset + limit) : null,
      sort: params?.sort === "name" ? { key: "name", order: params.order ?? "asc" } : null,
      facets,
      ...extra,
    };
  };
}

beforeEach(() => {
  deploymentMock.counts = undefined;
  navigationMock.query = "";
  apiMock.getAgentDetail.mockReset();
  apiMock.listAgents.mockReset();
  apiMock.listAgents.mockImplementation(pagingServer(AGENTS as Row[]));
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("AgentsPage list view", () => {
  it("renders KPIs and one dense agents table with each agent's status", async () => {
    render(<AgentsPage />);

    await waitFor(() => expect(screen.getByTestId("agents-table")).toBeInTheDocument());
    expect(screen.getByTestId("agents-kpis")).toBeInTheDocument();

    const table = within(screen.getByTestId("agents-table"));
    expect(table.getByText("Cursor")).toBeInTheDocument();
    expect(table.getByText("ClaudeDesktop")).toBeInTheDocument();
    expect(table.getByText("SomeBinary")).toBeInTheDocument();
    expect(table.getByText("not configured")).toBeInTheDocument();
    expect(apiMock.listAgents).toHaveBeenCalledWith(expect.objectContaining({ limit: 50, offset: 0 }), expect.any(AbortSignal));
  });

  it("searches on the server by name", async () => {
    render(<AgentsPage />);

    await waitFor(() => expect(screen.getByTestId("agents-table")).toBeInTheDocument());
    fireEvent.change(screen.getByPlaceholderText("Search agents or agent type"), { target: { value: "cursor" } });

    await waitFor(() => expect(within(screen.getByTestId("agents-table")).queryByText("ClaudeDesktop")).not.toBeInTheDocument());
    expect(within(screen.getByTestId("agents-table")).getByText("Cursor")).toBeInTheDocument();
    expect(apiMock.listAgents).toHaveBeenLastCalledWith(expect.objectContaining({ q: "cursor", offset: 0 }), expect.any(AbortSignal));
  });

  it("searches by agent type, as the placeholder promises", async () => {
    render(<AgentsPage />);

    await waitFor(() => expect(screen.getByTestId("agents-table")).toBeInTheDocument());
    fireEvent.change(screen.getByPlaceholderText("Search agents or agent type"), { target: { value: "desktop" } });

    await waitFor(() => expect(within(screen.getByTestId("agents-table")).queryByText("Cursor")).not.toBeInTheDocument());
    expect(within(screen.getByTestId("agents-table")).getByText("ClaudeDesktop")).toBeInTheDocument();
    expect(screen.getByTestId("agents-match-count")).toHaveTextContent("1 of 3 agents match");
  });

  it("filters by status and type chips that carry counts", async () => {
    render(<AgentsPage />);

    const chips = within(await screen.findByTestId("agents-filter-chips"));
    const statusGroup = within(chips.getByRole("group", { name: "Filter by status" }));
    expect(statusGroup.getByRole("button", { name: /^configured\s*2$/ })).toBeInTheDocument();
    fireEvent.click(statusGroup.getByRole("button", { name: /not configured\s*1/ }));

    await waitFor(() => expect(within(screen.getByTestId("agents-table")).queryByText("Cursor")).not.toBeInTheDocument());
    expect(within(screen.getByTestId("agents-table")).getByText("SomeBinary")).toBeInTheDocument();
    expect(statusGroup.getByRole("button", { name: /not configured/ })).toHaveAttribute("aria-pressed", "true");
    expect(apiMock.listAgents).toHaveBeenLastCalledWith(
      expect.objectContaining({ status: ["installed-not-configured"], offset: 0 }),
      expect.any(AbortSignal),
    );

    const typeGroup = within(screen.getByRole("group", { name: "Filter by type" }));
    expect(typeGroup.getByRole("button", { name: /cli\s*1/ })).toBeInTheDocument();
  });

  it("pages through the server's rows and keeps totals from the server", async () => {
    navigationMock.query = "size=25";
    const many = Array.from({ length: 60 }, (_, i) => ({
      name: `agent-${String(i).padStart(3, "0")}`, display_name: `agent-${String(i).padStart(3, "0")}`, agent_type: "cursor", status: "configured", source: "fleet", mcp_servers: [],
    }));
    apiMock.listAgents.mockImplementation(pagingServer(many));
    render(<AgentsPage />);

    await waitFor(() => expect(screen.getByText("Page 1 of 3 (60 agents)")).toBeInTheDocument());
    expect(within(screen.getByTestId("agents-table")).getByText("agent-000")).toBeInTheDocument();
    expect(within(screen.getByTestId("agents-table")).queryByText("agent-025")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Next/ }));

    await waitFor(() => expect(screen.getByText("Page 2 of 3 (60 agents)")).toBeInTheDocument());
    await waitFor(() => expect(within(screen.getByTestId("agents-table")).getByText("agent-025")).toBeInTheDocument());
    expect(apiMock.listAgents).toHaveBeenLastCalledWith(expect.objectContaining({ offset: 25, limit: 25 }), expect.any(AbortSignal));
  });

  it("sorts on the server from a column header", async () => {
    render(<AgentsPage />);

    await waitFor(() => expect(screen.getByTestId("agents-table")).toBeInTheDocument());
    fireEvent.click(within(screen.getByTestId("agents-table")).getByRole("button", { name: /^Name/ }));

    await waitFor(() =>
      expect(apiMock.listAgents).toHaveBeenLastCalledWith(expect.objectContaining({ sort: "name", order: "asc" }), expect.any(AbortSignal)),
    );
  });

  it("draws the sort indicator from the sort the server applied, not the one requested", async () => {
    navigationMock.query = "sort=findings&order=desc";
    render(<AgentsPage />);

    const table = await screen.findByTestId("agents-table");
    await waitFor(() => expect(within(table).getAllByText("Cursor").length).toBeGreaterThan(0));
    // The fake server only sorts by name and echoes null for anything else.
    for (const header of within(table).getAllByRole("columnheader")) {
      expect(String(header.getAttribute("aria-sort"))).not.toMatch(/ascending|descending/);
    }
    expect(screen.getByTestId("agents-sort-state")).toHaveTextContent("first-seen order");

    fireEvent.click(within(table).getByRole("button", { name: /^Name/ }));
    await waitFor(() =>
      expect(within(table).getByRole("columnheader", { name: /^Name/ })).toHaveAttribute("aria-sort", "ascending"),
    );
  });

  it("reads page, filters and sort from the URL", async () => {
    navigationMock.query = "q=cur&type=ide&sort=packages&order=asc&page=2&size=25";
    render(<AgentsPage />);

    await waitFor(() =>
      expect(apiMock.listAgents).toHaveBeenCalledWith(
        expect.objectContaining({ q: "cur", type: ["ide"], sort: "packages", order: "asc", offset: 25, limit: 25 }),
        expect.any(AbortSignal),
      ),
    );
  });

  it("takes summary cards from the server's population totals, not the visible page", async () => {
    apiMock.listAgents.mockImplementation(pagingServer(AGENTS as Row[], {
      count: 5000,
      summary: {
        agents: 5000, configured: 4800, not_configured: 200, mcp_servers: 9100, remote_servers: 12, packages: 40321,
        ecosystems: { npm: 40321 }, unique_credentials: 77, servers_with_credentials: 300, blocked_servers: 4,
      },
    }));
    render(<AgentsPage />);

    const kpis = within(await screen.findByTestId("agents-kpis"));
    expect(kpis.getByText("5,000")).toBeInTheDocument();
    expect(kpis.getByText("9,100")).toBeInTheDocument();
    expect(kpis.getByText("40,321")).toBeInTheDocument();
  });

  it("opens an agent detail drawer with servers, tools, and credentials", async () => {
    render(<AgentsPage />);

    await waitFor(() => expect(screen.getByTestId("agents-table")).toBeInTheDocument());
    fireEvent.click(within(screen.getByTestId("agents-table")).getByText("Cursor"));

    const detail = within(screen.getByTestId("agent-detail-Cursor"));
    expect(detail.getByText("github")).toBeInTheDocument();
    expect(detail.getByText("create_issue")).toBeInTheDocument();
    expect(detail.getByText("GITHUB_TOKEN")).toBeInTheDocument();

    const dialog = within(screen.getByRole("dialog"));
    expect(dialog.getByRole("link", { name: "Full detail" })).toHaveAttribute("href", "/agents?name=Cursor");
    expect(dialog.getByRole("link", { name: "Lifecycle graph" })).toHaveAttribute(
      "href",
      "/agents?name=Cursor&view=lifecycle"
    );
  });

  it.each(["", "invalid-capture-time"])("keeps unverified collection context explicit (%s)", async (captured_at) => {
    apiMock.listAgents.mockResolvedValue({ agents: [{ ...AGENTS[0], discovery_envelope: {
      envelope_version: 1, scan_mode: "unknown", redaction_status: "unknown", captured_at,
      discovery_scope: [], permissions_used: ["iam:GetRole"],
    } }] });
    render(<AgentsPage />);
    await waitFor(() => expect(screen.getByTestId("agents-table")).toBeInTheDocument());
    fireEvent.click(within(screen.getByTestId("agents-table")).getByText("Cursor"));
    const detail = within(screen.getByTestId("agent-detail-Cursor"));
    expect(detail.getByText("Collection context")).toBeInTheDocument();
    expect(detail.getByText("redaction: unknown")).toBeInTheDocument();
    expect(detail.getByText(/Capture time unknown/)).toBeInTheDocument();
    expect(detail.getByText("Reported permissions (1)")).toBeInTheDocument();
    expect(detail.queryByText(/Scan ran from/)).not.toBeInTheDocument();
    expect(detail.queryByText(/Invalid Date/)).not.toBeInTheDocument();
  });
});

describe("AgentsPage agent population", () => {
  const subtitle = () => screen.getByText(/Discovered AI clients\/hosts/);

  it("shows the canonical estate agent count and labels the host-discovered list as such", async () => {
    deploymentMock.counts = { agents: { total: 43, scan_id: "scan-9", basis: "graph_agents" } };
    render(<AgentsPage />);

    const kpis = within(await screen.findByTestId("agents-kpis"));
    expect(subtitle()).toHaveTextContent("with their MCP servers on this API host. 43 agent records in snapshot Open agent inventory");
    expect(within(subtitle()).getByRole("link", { name: "Open agent inventory" })).toHaveAttribute("href", "/inventory?type=agent");
    expect(kpis.getByText("Agents on this host")).toBeInTheDocument();
    expect(kpis.queryByText("Agents")).not.toBeInTheDocument();
  });

  it("keeps the estate count visible when nothing is configured on the API host", async () => {
    deploymentMock.counts = { agents: { total: 0, scan_id: null, basis: "graph_agents" } };
    apiMock.listAgents.mockResolvedValue({ scope: "local_discovery", agents: [] });
    render(<AgentsPage />);

    await waitFor(() => expect(subtitle()).toHaveTextContent("0 agent records in snapshot"));
    expect(within(subtitle()).getByRole("link", { name: "Open agent inventory" })).toBeInTheDocument();
  });

  it("labels a scanned-estate response as scanned agents, never as this API host", async () => {
    apiMock.listAgents.mockResolvedValue({
      scope: "scanned_estate",
      count: 1,
      agents: [
        {
          name: "project:sampleapp",
          agent_type: "custom",
          source: "project",
          status: "configured",
          config_path: "/work/sampleapp",
          mcp_servers: [
            { name: "github", surface: "mcp-server", packages: [], env: { GITHUB_PERSONAL_ACCESS_TOKEN: "***" } },
            { name: "filesystem", surface: "mcp-server", packages: [] },
            { name: "app", surface: "other", command: "project", packages: [{ name: "pyyaml", version: "5.3", ecosystem: "pypi" }] },
            { name: "ai-inventory", surface: "ai-inventory", packages: [] },
          ],
        },
      ],
    });
    render(<AgentsPage />);

    const kpis = within(await screen.findByTestId("agents-kpis"));
    expect(kpis.getByText("Scanned agents")).toBeInTheDocument();
    expect(kpis.queryByText("Agents on this host")).not.toBeInTheDocument();
    expect(subtitle()).not.toHaveTextContent("on this API host");
    // Manifest directories and the AI-inventory wrapper are not MCP servers.
    const mcpServersCell = kpis.getByText("MCP servers").parentElement!.parentElement!;
    expect(within(mcpServersCell).getByText("2")).toBeInTheDocument();
  });

  it("never claims an unlabelled population is on this host", async () => {
    apiMock.listAgents.mockResolvedValue({ agents: AGENTS });
    render(<AgentsPage />);

    const kpis = within(await screen.findByTestId("agents-kpis"));
    expect(kpis.getByText("Agents")).toBeInTheDocument();
    expect(kpis.queryByText("Agents on this host")).not.toBeInTheDocument();
    expect(subtitle()).not.toHaveTextContent("on this API host");
  });

  it("names the blocked tile for what it counts instead of implying no risk", async () => {
    render(<AgentsPage />);

    const kpis = within(await screen.findByTestId("agents-kpis"));
    expect(kpis.getByText("Launch-blocked servers")).toBeInTheDocument();
    expect(kpis.getByText(/vulnerabilities are on Findings/)).toBeInTheDocument();
    expect(kpis.queryByText("Blocked / risky")).not.toBeInTheDocument();
  });

  it("omits the estate count when the server does not report one", async () => {
    render(<AgentsPage />);

    const kpis = within(await screen.findByTestId("agents-kpis"));
    expect(kpis.getByText("Agents on this host")).toBeInTheDocument();
    expect(subtitle()).not.toHaveTextContent("agent records in snapshot");
    expect(screen.queryByRole("link", { name: "Open agent inventory" })).not.toBeInTheDocument();
  });
});


it("does not call an agent clean when no identity-linked findings are available", async () => {
  navigationMock.query = "name=agent-id-1";
  apiMock.getAgentDetail.mockResolvedValue({
    agent: { ...AGENTS[0], mcp_servers: [] },
    summary: { total_servers: 0, total_packages: 0, total_tools: 0, total_credentials: 0, total_vulnerabilities: 0, severity_breakdown: {} },
    blast_radius: [], credentials: [], fleet: null,
  });
  render(<AgentsPage />);
  expect(await screen.findByText("No attributed findings")).toHaveAttribute("title", expect.stringContaining("coverage may be incomplete"));
  expect(screen.queryByText("Clean")).not.toBeInTheDocument();
  expect(apiMock.getAgentDetail).toHaveBeenCalledWith("agent-id-1");
});

describe("AgentsPage count scope", () => {
  it("labels server tiles as configured entries, packages as references across agents, and points at the inventory basis", async () => {
    render(<AgentsPage />);
    const kpis = within(await screen.findByTestId("agents-kpis"));
    for (const [label, caption] of [["MCP servers", /configured/], ["Package references", /across agents/]] as const) {
      const cell = kpis.getByText(label).parentElement!.parentElement!;
      expect(within(cell).getByText(caption)).toBeInTheDocument();
      expect(cell).toHaveAttribute("title", expect.stringMatching(/Asset inventory/));
    }
    expect(kpis.getByText("Agents on this host").parentElement!.parentElement!).toHaveAttribute(
      "title",
      expect.stringMatching(/Asset inventory/),
    );
  });
});
