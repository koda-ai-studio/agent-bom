import { render, screen, fireEvent, within, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ExposurePathCommandCenter } from "@/components/exposure-path-command-center";
import type { ExposurePath } from "@/lib/exposure-path";
import { ASSET_KINDS, type AssetKind } from "@/lib/asset-icon-registry";

beforeEach(() => { HTMLElement.prototype.scrollIntoView = vi.fn(); });

describe("risk basis on paths without a finding", () => {
  it("states the recorded basis instead of an 'unknown severity' pill", () => {
    const configured: ExposurePath = {
      ...basePath, id: "path-cv", severity: "unknown", findings: [], evidence: undefined,
      reachability: "likely", reachabilityBasis: ["recorded_identifier_match"],
      hops: basePath.hops.slice(0, 2), target: { id: "server:database", label: "database", role: "server" },
    };
    const { container } = render(<ExposurePathCommandCenter path={configured} />);
    expect(container.querySelector(".ep-severity")).toBeNull();
    expect(screen.queryByText(/unknown severity/i)).toBeNull();
    expect(screen.getByTestId("path-risk-basis")).toHaveTextContent("Recorded identifier match");
  });

  it("keeps the severity pill when a finding is on the path", () => {
    const { container } = render(<ExposurePathCommandCenter path={basePath} />);
    expect(container.querySelector(".ep-severity")).toHaveTextContent("critical severity");
    expect(screen.queryByTestId("path-risk-basis")).toBeNull();
  });
});

const basePath: ExposurePath = {
  id: "path-1",
  label: "analyst-agent -> database -> werkzeug -> CVE-2026-0002",
  summary: "Agent reaches a vulnerable package through the database MCP server.",
  riskScore: 9.6,
  severity: "critical",
  source: { id: "agent:analyst", label: "analyst-agent", role: "agent" },
  target: { id: "vuln:werkzeug:CVE-2026-0002", label: "CVE-2026-0002", role: "finding", severity: "critical" },
  hops: [
    { id: "agent:analyst", label: "analyst-agent", role: "agent" },
    { id: "server:database", label: "database", role: "server" },
    { id: "pkg:werkzeug", label: "werkzeug@2.2.2", role: "package", severity: "critical" },
    { id: "vuln:werkzeug:CVE-2026-0002", label: "CVE-2026-0002", role: "finding", severity: "critical" },
    { id: "tool:execute_sql", label: "execute_sql", role: "tool" },
    { id: "cred:DATABASE_URL", label: "DATABASE_URL", role: "credential" },
  ],
  relationships: [
    {
      id: "agent->server",
      source: "agent:analyst",
      target: "server:database",
      relationship: "uses",
      direction: "directed",
      traversable: true,
      confidence: "observed",
    },
    {
      id: "pkg->vuln",
      source: "pkg:werkzeug",
      target: "vuln:werkzeug:CVE-2026-0002",
      relationship: "vulnerable_to",
      direction: "directed",
      traversable: true,
      confidence: "scanner",
    },
  ],
  nodeIds: ["agent:analyst", "server:database", "pkg:werkzeug", "vuln:werkzeug:CVE-2026-0002"],
  edgeIds: ["agent->server", "pkg->vuln"],
  findings: ["CVE-2026-0002"],
  affectedAgents: ["analyst-agent"],
  affectedServers: ["database"],
  reachableTools: ["execute_sql"],
  exposedCredentials: ["DATABASE_URL"],
  dependencyContext: {
    packageName: "werkzeug",
    packageVersion: "2.2.2",
    ecosystem: "pypi",
    serverName: "database",
  },
  fix: {
    label: "Upgrade werkzeug",
    version: "2.2.3",
  },
  evidence: {
    cvssScore: 9.8,
    epssScore: 0.834,
    isKev: true,
    attackVectorSummary: "Database MCP server exposes SQL execution.",
  },
};

/**
 * Longest board the product has to frame: agent -> server -> package -> finding
 * -> 3 tools -> 3 credentials -> data store. It remains wider than the
 * readable board budget even after compact node sizing.
 */
const longPath: ExposurePath = {
  ...basePath,
  id: "path-long",
  hops: [
    { id: "agent:cursor", label: "Cursor", role: "agent" },
    { id: "server:shell-runner", label: "shell-runner-server", role: "server" },
    { id: "pkg:pyyaml", label: "pyyaml@5.3", role: "package" },
    { id: "vuln:CVE-2020-14343", label: "CVE-2020-14343", role: "finding" },
    { id: "tool:run_shell", label: "run_shell", role: "tool" },
    { id: "tool:exec_command", label: "exec_command", role: "tool" },
    { id: "tool:read_file", label: "read_file", role: "tool" },
    { id: "cred:SNOWFLAKE_PASSWORD", label: "SNOWFLAKE_PASSWORD", role: "credential" },
    { id: "cred:DATABASE_URL", label: "DATABASE_URL", role: "credential" },
    { id: "cred:AWS_SECRET_ACCESS_KEY", label: "AWS_SECRET_ACCESS_KEY", role: "credential" },
    { id: "store:warehouse", label: "prod-warehouse", role: "environment" },
  ],
};

const referencePath: ExposurePath = {
  ...basePath,
  id: "reference-path",
  hops: longPath.hops.slice(0, 8),
};

describe("ExposurePathCommandCenter", () => {
  it.each([true, false])("positions the graph immediately on mobile=%s before navigation takes focus", async (mobile) => {
    const scrollIntoView = vi.fn();
    vi.stubGlobal("matchMedia", vi.fn(() => ({ matches: mobile })));
    const original = HTMLElement.prototype.scrollIntoView;
    HTMLElement.prototype.scrollIntoView = scrollIntoView;
    try {
      render(<ExposurePathCommandCenter path={basePath} graphSlot={<div>Graph navigation</div>} />);
      fireEvent.click(screen.getByRole("button", { name: /^Graph$/ }));
      await waitFor(() => expect(scrollIntoView).toHaveBeenCalledWith({ block: "start", behavior: "instant" }));
    } finally {
      HTMLElement.prototype.scrollIntoView = original;
      vi.unstubAllGlobals();
    }
  });

  it("keeps the path outcome visible and tucks secondary metrics and assessments into a collapsible summary", () => {
    render(<ExposurePathCommandCenter path={{ ...basePath, provenance: { source: "fixture", scanId: "scan-scope" } }} />);
    expect(screen.getByTestId("path-finding-context")).not.toBeVisible();
    expect(screen.getByRole("region", { name: "Path evidence assessment" })).not.toBeVisible();
    fireEvent.click(screen.getByText(/Path context & evidence/));
    expect(screen.getByTestId("path-finding-context")).toHaveTextContent("werkzeug@2.2.2");
    expect(screen.getByTestId("path-finding-context")).not.toHaveTextContent("CVE-2026-0002");
    expect(screen.getByRole("heading", { level: 2 })).toHaveTextContent("Analyst Agent → CVE-2026-0002");
    expect(screen.getByRole("region", { name: "Path evidence assessment" })).toHaveTextContent("Unknown");
    expect(screen.getByRole("region", { name: "Path evidence assessment" })).toHaveTextContent("Not assessed");
    expect(screen.getByText("Snapshot: scan-scope")).not.toBeVisible();
    fireEvent.click(screen.getByText("Evidence & relationships"));
    expect(screen.getByText("Snapshot: scan-scope")).toBeVisible();
    expect(screen.getByText("Recorded relationships do not establish effective permission, exploitation or successful data access.")).toBeVisible();
  });

  it("renders a compact path header with collapsed evidence by default", () => {
    render(
      <ExposurePathCommandCenter
        path={basePath}
        actions={[{ title: "Validate the lead finding", detail: "Open CVE evidence.", href: "/findings?cve=CVE-2026-0002" }]}
      />,
    );

    expect(screen.getByRole("heading", { level: 2 })).toHaveTextContent(
      "Analyst Agent → CVE-2026-0002",
    );
    expect(screen.getByRole("heading", { level: 2 })).toBeVisible();
    expect(screen.queryByTestId("exposure-path-hop-title")).not.toBeInTheDocument();
    expect(screen.queryByText("What is exposed")).not.toBeInTheDocument();
    expect(screen.getByText(/Path context & evidence/)).toHaveTextContent(/· 1 agent on this path$/);
    expect(screen.getByText("Evidence & relationships")).toBeInTheDocument();
    expect(screen.queryByText("Evidence drawer")).not.toBeVisible();
    expect(screen.getByText("Validate the lead finding")).toBeInTheDocument();
    expect(screen.getByText("Open CVE evidence.")).not.toBeVisible();
    fireEvent.click(screen.getByText("Evidence & relationships"));
    expect(screen.getByText("Open CVE evidence.")).toBeVisible();
  });

  it("keeps raw finding identifiers in evidence and does not invent a path summary", () => {
    const findingId = "2176ecf3-971b-5006-9b0c-f59ff11cc7ff";
    render(<ExposurePathCommandCenter path={{ ...basePath, findings: [findingId], summary: undefined }} />);
    const header = screen.getByRole("heading", { level: 2 }).closest(".ep-header");
    expect(header).not.toHaveTextContent(findingId);
    expect(screen.getByText(findingId)).not.toBeVisible();
    fireEvent.click(screen.getByText("Evidence & relationships"));
    expect(screen.getByText(findingId)).toBeVisible();
    expect(screen.queryByText(/inherits downstream credential and tool exposure/)).not.toBeInTheDocument();
  });

  it("keeps the decision proof and action visible while technical analysis is disclosed", () => {
    render(
      <ExposurePathCommandCenter
        path={basePath}
        actions={[{ title: "Open remediation", detail: "Review the patch.", href: "/remediation" }]}
        techniquesSlot={<div>Path evidence complete from seven receipts</div>}
        detailsSlot={<div>Mapped ATT&amp;CK analysis</div>}
      />,
    );

    expect(screen.getByText("Path evidence complete from seven receipts")).toBeVisible();
    expect(screen.getByText("Open remediation")).toBeVisible();
    expect(screen.getByText("Mapped ATT&CK analysis")).not.toBeVisible();
  });

  it("never wraps the target advisory id inside the path title", () => {
    render(<ExposurePathCommandCenter path={basePath} />);
    const title = screen.getByRole("heading", { level: 2 });
    expect(title).toHaveTextContent("Analyst Agent → CVE-2026-0002");
    const id = title.querySelector("[data-advisory-id]");
    expect(id).toHaveTextContent("CVE-2026-0002");
    expect(id?.className).toContain("whitespace-nowrap");
  });

  it("gives the title a full mobile row and keeps the summary readable", () => {
    render(<ExposurePathCommandCenter path={basePath} />);

    const title = screen.getByRole("heading", { level: 2 });
    expect(title.closest(".ep-header-copy")).not.toBeNull();
    expect(screen.getByText(basePath.summary!)).not.toBeVisible();
    fireEvent.click(screen.getByText("Evidence & relationships"));
    expect(screen.getByText("Source summary · consult assessments and receipts")).toBeVisible();
    expect(screen.getByText(basePath.summary!)).toBeVisible();
  });

  it("presents a single-node risk signal as one node instead of zero hops", () => {
    const resource = { id: "resource-1", label: "Prod Bastion", role: "server" as const };
    render(
      <ExposurePathCommandCenter
        path={{
          ...basePath,
          source: resource,
          target: resource,
          hops: [resource],
          affectedAgents: [],
        }}
      />,
    );

    fireEvent.click(screen.getByText(/Path context & evidence/));
    expect(screen.getByText("Path span")).toBeInTheDocument();
    expect(screen.getByText("1 node")).toBeInTheDocument();
    expect(screen.queryByText("Hops")).not.toBeInTheDocument();
  });

  it("shows one representation at a time and defaults to the path view", () => {
    render(<ExposurePathCommandCenter path={basePath} />);

    // Path view: the selected-path DAG is rendered; the neighbor list and the
    // interactive-graph hint are not stacked underneath it.
    expect(
      screen.getByRole("img", { name: /Selected exposure path graph for/ }),
    ).toBeInTheDocument();
    expect(screen.queryByText("Expand path neighbors")).not.toBeInTheDocument();
    expect(
      screen.queryByText(/Interactive graph opens below/),
    ).not.toBeInTheDocument();
  });

  it("switches to the neighbor list and the interactive-graph hint via the toggle", () => {
    const onViewChange = vi.fn();
    render(
      <ExposurePathCommandCenter
        path={basePath}
        view="list"
        onViewChange={onViewChange}
      />,
    );

    // Controlled "list" view swaps the DAG for the neighbor explorer.
    expect(screen.getByText("Expand path neighbors")).toBeInTheDocument();
    expect(
      screen.queryByRole("img", { name: /Selected exposure path graph for/ }),
    ).not.toBeInTheDocument();

    // The toggle reports view changes so the page can render the interactive
    // graph on demand.
    fireEvent.click(screen.getByRole("button", { name: /Graph/ }));
    expect(onViewChange).toHaveBeenCalledWith("graph");
  });

  it("renders the recorded path when an interactive graph is unavailable", () => {
    render(<ExposurePathCommandCenter path={basePath} view="graph" onViewChange={vi.fn()} />);

    expect(screen.queryByText(/Interactive graph loads here/)).not.toBeInTheDocument();
    expect(
      screen.getByRole("img", { name: /Selected exposure path graph for/ }),
    ).toBeInTheDocument();
  });

  it("keeps every long-path hop available in the ordered lane", () => {
    render(<ExposurePathCommandCenter path={longPath} />);

    const orderedPath = screen.getByTestId("exposure-path-sequence");
    expect(within(orderedPath).getByText("Cursor")).toBeInTheDocument();
    expect(within(orderedPath).getByText("run_shell")).toBeInTheDocument();
    expect(within(orderedPath).getByText("exec_command")).toBeInTheDocument();
    expect(within(orderedPath).getByText("DATABASE_URL")).toBeInTheDocument();
    expect(within(orderedPath).getByText("prod-warehouse")).toBeInTheDocument();
    expect(within(orderedPath).getByText("11. Environment")).toBeInTheDocument();
    expect(within(orderedPath).queryByText(/hops hidden/)).not.toBeInTheDocument();
    expect(screen.queryByRole("img", { name: /Selected exposure path graph for/ })).not.toBeInTheDocument();
    expect(screen.getByText("All 11 steps available in order.")).toBeInTheDocument();
  });

  it("shows every hop in the eight-hop reference proof without a hidden summary", () => {
    render(<ExposurePathCommandCenter path={referencePath} />);

    const board = screen.getByRole("img", { name: /Selected exposure path graph for/ });
    expect(within(board).getByText("Agent: Cursor")).toBeInTheDocument();
    expect(within(board).getByText("Credential: SNOWFLAKE_PASSWORD")).toBeInTheDocument();
    expect(within(board).queryByText(/hops hidden/)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Show all 8 hops/ })).not.toBeInTheDocument();

    const mobileSequence = screen.getByRole("list", {
      name: /Selected exposure path ordered steps for/,
    });
    expect(mobileSequence.parentElement).toHaveClass("sm:hidden");
    expect(within(mobileSequence).getByText("1. Agent")).toBeInTheDocument();
    expect(within(mobileSequence).getByText("8. Credential")).toBeInTheDocument();
    expect(within(mobileSequence).getByText("Cursor")).toBeInTheDocument();
    expect(within(mobileSequence).getByText("SNOWFLAKE_PASSWORD")).toBeInTheDocument();
  });

  it("renders the canonical node kind instead of a broad styling role", () => {
    const path = {
      ...longPath,
      hops: longPath.hops.map((hop, index) =>
        index === 2 ? { ...hop, kindLabel: "Container" } : hop,
      ),
    };
    render(<ExposurePathCommandCenter path={path} />);

    const orderedPath = screen.getByTestId("exposure-path-sequence");
    expect(within(orderedPath).getByText("3. Container")).toBeInTheDocument();
    expect(within(orderedPath).queryByText("3. Server")).not.toBeInTheDocument();
  });

  it("round-trips the long-chain board between collapsed and fully expanded", () => {
    render(<ExposurePathCommandCenter path={longPath} />);

    const toggle = screen.getByRole("button", { name: "Expand graph workspace" });
    expect(toggle).toHaveAttribute("aria-expanded", "false");

    fireEvent.click(toggle);
    const expandedBoard = screen.getByRole("img", { name: /Selected exposure path graph for/ });
    expect(within(expandedBoard).getByText("run_shell")).toBeInTheDocument();
    expect(within(expandedBoard).getByText("exec_command")).toBeInTheDocument();
    expect(within(expandedBoard).getByText("DATABASE_URL")).toBeInTheDocument();
    expect(within(expandedBoard).queryByText("+9 hops hidden")).not.toBeInTheDocument();
    // Expanded board renders at 1x and scrolls horizontally instead of scaling.
    expect(Number(expandedBoard.getAttribute("width"))).toBeGreaterThan(1408);
    expect(screen.getByTestId("exposure-path-graph-scroll")).toHaveClass("overflow-x-auto");

    const collapse = screen.getByRole("button", { name: "Return to ordered path" });
    expect(collapse).toHaveAttribute("aria-expanded", "true");
    fireEvent.click(collapse);
    expect(screen.queryByRole("img", { name: /Selected exposure path graph for/ })).not.toBeInTheDocument();
    expect(within(screen.getByTestId("exposure-path-sequence")).getByText("run_shell")).toBeInTheDocument();
  });

  it("re-enters the fit-first frame when a different path is selected", () => {
    const { rerender } = render(<ExposurePathCommandCenter path={longPath} />);
    fireEvent.click(screen.getByRole("button", { name: "Expand graph workspace" }));
    expect(screen.getByRole("button", { name: "Return to ordered path" })).toBeInTheDocument();

    // Selecting another long path must not inherit the expanded board — the
    // first frame of a new investigation has to fit again.
    rerender(<ExposurePathCommandCenter path={{ ...longPath, id: "path-long-2" }} />);
    expect(screen.getByRole("button", { name: "Expand graph workspace" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Return to ordered path" })).not.toBeInTheDocument();
  });

  it("does not offer a collapse toggle for a path that already fits", () => {
    render(<ExposurePathCommandCenter path={{ ...basePath, hops: basePath.hops.slice(0, 4) }} />);

    expect(screen.queryByRole("button", { name: /Expand graph workspace/ })).not.toBeInTheDocument();
    expect(screen.getByTestId("exposure-path-graph-scroll")).not.toHaveClass("overflow-x-auto");
  });

  it("renders the interactive graph inline in graph view instead of an 'opens below' placeholder", () => {
    render(
      <ExposurePathCommandCenter
        path={basePath}
        view="graph"
        onViewChange={vi.fn()}
        graphSlot={<div data-testid="inline-investigation-graph">live graph</div>}
      />,
    );

    // The graph is shown right here, in the Graph slot — not a placeholder
    // pointing at a separate panel further down the page.
    expect(screen.getByTestId("inline-investigation-graph")).toBeInTheDocument();
    expect(screen.queryByText(/Interactive graph loads here/)).not.toBeInTheDocument();
    expect(screen.queryByText(/opens below/)).not.toBeInTheDocument();
    // Only the graph slot renders — the path DAG is not stacked underneath.
    expect(
      screen.queryByRole("img", { name: /Selected exposure path graph for/ }),
    ).not.toBeInTheDocument();
  });
});

it("retains relationships beyond the eighth receipt", () => {
  const relationships = Array.from({length: 13}, (_, i) => ({id: `r${i}`, source: `a${i}`, target: `b${i}`, relationship: `relation_${i}`}));
  render(<ExposurePathCommandCenter path={{...basePath, relationships}} />);
  expect(screen.getByText("Relation 12")).toBeInTheDocument();
});

 it("keeps a long digest compact and exposes its complete value on demand", () => {
  const digest = `Digest sha256:${"a".repeat(64)}`;
  const path = {...longPath, hops: longPath.hops.map((hop, index) => index === 2 ? {...hop, subtitle: digest} : hop)};
  render(<ExposurePathCommandCenter path={path} />);
  const toggle = screen.getByText("Digest sha256:aaaaaaaaaaaa…");
  expect(toggle).toBeVisible();
  expect(screen.getByText(digest, {selector: "code"})).not.toBeVisible();
  fireEvent.click(toggle);
  expect(screen.getByText(digest, {selector: "code"})).toBeVisible();
 });


it("uses recorded endpoints even when a source title claims unassessed exploitation", () => {
  const sourceTitle = "Exploitable agent reaches private data";
  render(<ExposurePathCommandCenter path={basePath} title={sourceTitle} />);
  expect(screen.getByRole("heading", { level: 2 })).toHaveTextContent("Analyst Agent → CVE-2026-0002");
  expect(screen.getByRole("heading", { level: 2 })).not.toHaveTextContent(/exploitable|reaches/i);
  expect(screen.getByText(sourceTitle)).not.toBeVisible();
  fireEvent.click(screen.getByText("Evidence & relationships"));
  fireEvent.click(screen.getByText("Source-provided title"));
  expect(screen.getByText(sourceTitle)).toBeVisible();
  expect(screen.getByText("This label is not an assessment of reachability, exploitation, or impact.")).toBeVisible();
});


it("keeps unavailable assessments visible when a legacy snapshot has no dimensions", () => {
  render(<ExposurePathCommandCenter path={basePath} />);
  fireEvent.click(screen.getByText(/Path context & evidence/));
  const assessment = screen.getByRole("region", { name: "Path evidence assessment" });
  expect(assessment).toHaveTextContent("ReachabilityUnknown");
  expect(assessment).toHaveTextContent("ExploitabilityNot assessed");
  expect(assessment).toHaveTextContent("Assessment completenessUnavailable");
});

it("preserves distinct same-name agent references without duplicate render keys", () => {
  const error = vi.spyOn(console, "error").mockImplementation(() => {});
  try {
    render(<ExposurePathCommandCenter path={{ ...basePath, affectedAgents: ["Reviewer", "Reviewer"] }} />);
    fireEvent.click(screen.getByText("Evidence & relationships"));
    expect(screen.getAllByText("Reviewer", { exact: true })).toHaveLength(2);
    expect(error.mock.calls.flat().join(" ")).not.toMatch(/same key/i);
  } finally {
    error.mockRestore();
  }
});


it("scrolls to the graph only after a controlled view commits its section", () => {
  const scroll = vi.fn();
  const original = HTMLElement.prototype.scrollIntoView;
  HTMLElement.prototype.scrollIntoView = scroll;
  try {
    const props = { path: basePath, onViewChange: vi.fn(), graphSlot: <div>Graph loaded</div> };
    const { rerender } = render(<ExposurePathCommandCenter {...props} view="path" />);
    fireEvent.click(screen.getByRole("button", { name: "Graph" }));
    expect(scroll).not.toHaveBeenCalled();
    rerender(<ExposurePathCommandCenter {...props} view="graph" />);
    expect(scroll).toHaveBeenCalledWith({ block: "start", behavior: "instant" });
  } finally {
    HTMLElement.prototype.scrollIntoView = original;
  }
});

it("does not scroll the page when the graph view is the initial view", () => {
  const scroll = vi.fn();
  const original = HTMLElement.prototype.scrollIntoView;
  HTMLElement.prototype.scrollIntoView = scroll;
  try {
    const props = { path: basePath, onViewChange: vi.fn(), graphSlot: <div>Graph loaded</div> };
    const { rerender } = render(<ExposurePathCommandCenter {...props} view="graph" />);
    render(<ExposurePathCommandCenter path={basePath} graphSlot={<div>Uncontrolled graph</div>} />);
    expect(scroll).not.toHaveBeenCalled();
    rerender(<ExposurePathCommandCenter {...props} view="path" />);
    rerender(<ExposurePathCommandCenter {...props} view="graph" />);
    expect(scroll).toHaveBeenCalledTimes(1);
  } finally {
    HTMLElement.prototype.scrollIntoView = original;
  }
});

describe("path step glyphs", () => {
  function glyphClass(element: Element | null): string {
    return [...(element?.querySelector("svg")?.classList ?? [])].filter((name) => name.startsWith("lucide-")).sort().join(" ");
  }

  function registryClass(kind: AssetKind): string {
    const Icon = ASSET_KINDS[kind].icon;
    const { container, unmount } = render(<Icon />);
    const value = glyphClass(container);
    unmount();
    return value;
  }

  it("draws each hop with its entity's registry glyph, not the coarse path role", () => {
    const hops: ExposurePath["hops"] = [
      { id: "agent:analyst", label: "analyst-agent", role: "agent", entityType: "agent" },
      { id: "container:api", label: "api", role: "server", entityType: "container", assetKind: "workload", kindLabel: "Workload" },
      { id: "container:img", label: "registry.local/api", role: "server", entityType: "container", assetKind: "image", kindLabel: "Image" },
      { id: "server:database", label: "database", role: "server", entityType: "server" },
      { id: "pkg:werkzeug", label: "werkzeug@2.2.2", role: "package", entityType: "package" },
      { id: "user:ops", label: "ops", role: "agent", entityType: "user" },
      { id: "env:prod", label: "prod", role: "environment" },
      { id: "cluster:prod", label: "prod", role: "cluster" },
    ];
    render(<ExposurePathCommandCenter path={{ ...basePath, hops }} />);
    const steps = within(screen.getAllByTestId("exposure-path-sequence")[0]!).getAllByRole("listitem");
    const drawn = steps.map((step) => glyphClass(step.querySelector(".ep-sequence-icon")));
    expect(drawn).toEqual(
      (["agent", "workload", "image", "mcp_server", "package", "user", "environment", "cluster"] as AssetKind[]).map(registryClass),
    );
    expect(new Set(drawn).size).toBe(drawn.length);
  });
});
