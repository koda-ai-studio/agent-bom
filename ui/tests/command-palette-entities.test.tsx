import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useState } from "react";

import { CommandPalette } from "@/components/command-palette";
import { ENTITY_SEARCH_TYPES, entitySearchResults, rankByName } from "@/lib/command-entity-search";
import type { UnifiedNode } from "@/lib/graph-schema";

vi.mock("next/link", () => ({
  default: ({ href, children, ...rest }: { href: string; children: React.ReactNode; [key: string]: unknown }) => <a href={href} {...rest}>{children}</a>,
}));

const node = (id: string, entity_type: string, label: string) => ({ id, entity_type, label }) as unknown as UnifiedNode;

describe("entitySearchResults", () => {
  it("links each entity to its detail or graph view and collapses advisory occurrences", () => {
    const results = entitySearchResults([
      node("vuln:CVE-2023-36258", "vulnerability", "CVE-2023-36258"),
      node("vuln:demo-estate:16530e6c", "vulnerability", "CVE-2023-36258: langchain@0.0.150"),
      node("agent:langchain-service", "agent", "langchain-service"),
      node("package:pypi:langchain@0.0.150:dce8", "package", "langchain@0.0.150"),
      node("server:llm-orchestrator", "server", "llm-orchestrator-server"),
    ]);
    expect(results).toEqual([
      { key: "cve:CVE-2023-36258", label: "CVE-2023-36258", kind: "Advisory", href: "/findings?q=CVE-2023-36258" },
      { key: "agent:langchain-service", label: "langchain-service", kind: "Agent", href: "/security-graph?lens=lineage&investigate=1&root=agent%3Alangchain-service&node=agent%3Alangchain-service" },
      { key: "package:langchain@0.0.150", label: "langchain@0.0.150", kind: "Package", href: "/security-graph?lens=attack-path&node=package%3Apypi%3Alangchain%400.0.150%3Adce8" },
      { key: "server:llm-orchestrator", label: "llm-orchestrator-server", kind: "MCP server", href: "/security-graph?lens=attack-path&node=server%3Allm-orchestrator" },
    ]);
  });
});

it("lists a package once when several occurrences share its name and version", () => {
  const results = entitySearchResults([
    node("package:pypi:langchain@0.0.150:aaa", "package", "langchain@0.0.150"),
    node("package:pypi:langchain@0.0.150:bbb", "package", "langchain@0.0.150"),
  ]);
  expect(results.map((result) => result.label)).toEqual(["langchain@0.0.150"]);
});

function Harness({ search }: { search: (query: string) => Promise<ReturnType<typeof entitySearchResults>> }) {
  const [query, setQuery] = useState("");
  return <CommandPalette query={query} setQuery={setQuery} onClose={vi.fn()} links={[]} searchEntities={search} />;
}

describe("CommandPalette entity search", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("debounces, ignores one-letter queries and shows linked entity results", async () => {
    const search = vi.fn(async () => [{ key: "agent:a", label: "langchain-service", kind: "Agent", href: "/agents?name=langchain-service" }]);
    render(<Harness search={search} />);
    const input = screen.getByPlaceholderText(/Search pages, CVEs, agents/);
    fireEvent.change(input, { target: { value: "l" } });
    await act(async () => { await vi.advanceTimersByTimeAsync(400); });
    expect(search).not.toHaveBeenCalled();
    fireEvent.change(input, { target: { value: "la" } });
    fireEvent.change(input, { target: { value: "lang" } });
    await act(async () => { await vi.advanceTimersByTimeAsync(400); });
    expect(search).toHaveBeenCalledTimes(1);
    expect(search).toHaveBeenCalledWith("lang");
    expect(screen.getByRole("link", { name: /langchain-service/ })).toHaveAttribute("href", "/agents?name=langchain-service");
  });

  it("says when entity search failed instead of showing nothing", async () => {
    render(<Harness search={vi.fn(async () => { throw new Error("offline"); })} />);
    fireEvent.change(screen.getByPlaceholderText(/Search pages, CVEs, agents/), { target: { value: "zzz" } });
    await act(async () => { await vi.advanceTimersByTimeAsync(400); });
    expect(screen.getByRole("status")).toHaveTextContent("Entity search is unavailable");
  });
});

it("finds data stores and cloud resources and lists exact, then prefix, name matches first", () => {
  const results = entitySearchResults([
    node("vuln:CVE-2026-1", "vulnerability", "CVE-2026-1: audit-evidence-staging-2 exporter"),
    node("aws:bucket:2:audit-evidence-staging-2-archive", "data_store", "audit-evidence-staging-2-archive"),
    node("aws:bucket:1:audit-evidence-staging-2", "data_store", "audit-evidence-staging-2"),
    node("aws:ec2:i-1", "cloud_resource", "prod-bastion"),
  ]);
  expect(results.find((result) => result.key === "aws:ec2:i-1")).toMatchObject({ kind: "Cloud resource", href: "/security-graph?lens=lineage&investigate=1&root=aws%3Aec2%3Ai-1&node=aws%3Aec2%3Ai-1" });
  expect(rankByName(results, "Audit-Evidence-Staging-2").map((result) => result.key).slice(0, 2)).toEqual([
    "aws:bucket:1:audit-evidence-staging-2",
    "aws:bucket:2:audit-evidence-staging-2-archive",
  ]);
  expect(ENTITY_SEARCH_TYPES).toEqual(expect.arrayContaining(["data_store", "cloud_resource"]));
});
