"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { RouteLine } from "@/components/agent-architecture/route-line";
import { Drawer } from "@/components/drawer";
import { severityStyle } from "@/components/attack-path-graph-node";
import { EvalSuiteList } from "@/components/eval-coverage-panel";
import { api } from "@/lib/api";
import { parseEvalSuite, type EvalSuiteRef } from "@/lib/eval-coverage";
import { buildFindingAssetHref } from "@/lib/finding-investigation-href";
import { FLOW_KIND_LABEL, frameworkLabel, severityRank, type ArchitectureModel, type ArchitectureNode } from "@/lib/agent-architecture-model";

type Finding = { id: string; label: string; severity: string };
type FindingList = { status: "loading" | "ready" | "error"; items: Finding[] };
const FINDING_READ_LIMIT = 100;
const CVE = /^CVE-\d{4}-\d+$/i;
const LINK = "font-medium text-[color:var(--accent)] underline-offset-2 hover:underline";

function useFindings(agentId: string | null, expected: number, scanId: string): FindingList {
  const [list, setList] = useState<FindingList & { for: string | null }>({ status: "loading", items: [], for: null });
  useEffect(() => {
    if (!agentId || expected === 0) return;
    let cancelled = false;
    api.getGraphNodeNeighbors(agentId, { scanId: scanId || undefined, direction: "out", limit: FINDING_READ_LIMIT })
      .then(response => {
        const ids = new Set(response.edges.filter(edge => edge.source === agentId && edge.relationship === "vulnerable_to").map(edge => edge.target));
        const items = response.neighbors.filter(node => ids.has(node.id))
          .map(node => ({ id: node.id, label: node.label || node.id, severity: String(node.severity ?? "") }))
          .sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || a.label.localeCompare(b.label));
        if (!cancelled) setList({ status: "ready", items, for: agentId });
      })
      .catch(() => { if (!cancelled) setList({ status: "error", items: [], for: agentId }); });
    return () => { cancelled = true; };
  }, [agentId, expected, scanId]);
  return list.for === agentId ? list : { status: "loading", items: [] };
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="space-y-1.5">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-ink-tertiary">{title}</h3>
      {children}
    </section>
  );
}

function Names({ items, empty }: { items: string[]; empty: string }) {
  if (items.length === 0) return <p className="text-sm text-ink-secondary">{empty}</p>;
  return <ul className="flex flex-wrap gap-1.5">{items.map(item => <li key={item} className="rounded-md border border-outline bg-surface-elevated px-2 py-0.5 font-mono text-[13px] text-foreground">{item}</li>)}</ul>;
}

function Findings({ node, scanId }: { node: ArchitectureNode; scanId: string }) {
  const list = useFindings(node.agent ? node.id : null, node.findings, scanId);
  if (node.findings === 0) return <p className="text-sm text-ink-secondary">No findings recorded on this agent.</p>;
  return (
    <div className="space-y-2">
      <p className="text-sm text-foreground">{node.findings} {node.findings === 1 ? "finding" : "findings"} · worst {node.findingSeverity || "unrated"}</p>
      {list.status === "loading" && <p className="text-sm text-ink-secondary">Loading the finding list…</p>}
      {list.status === "error" && <p className="text-sm text-ink-secondary">The finding list could not be loaded; the count above is from the architecture read.</p>}
      {list.status === "ready" && (
        <ul className="divide-y divide-[color:var(--border-subtle)] rounded-lg border border-outline">
          {list.items.map(item => {
            const cve = item.label.match(CVE)?.[0];
            return (
              <li key={item.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-sm">
                <span className="rounded-full border px-2 py-0.5 text-xs font-semibold capitalize" style={severityStyle(item.severity)}>{item.severity || "unrated"}</span>
                <span className="min-w-0 flex-1 truncate font-medium text-foreground">{item.label}</span>
                <Link className={LINK} href={buildFindingAssetHref({ nodeId: node.id, findingId: item.id, scanId })}>Investigate</Link>
                {cve && <Link className={LINK} aria-label={`Open ${cve} in findings`} href={`/findings?${new URLSearchParams({ cve })}`}>Findings</Link>}
              </li>
            );
          })}
        </ul>
      )}
      {list.status === "ready" && list.items.length < node.findings && (
        <p className="text-xs text-ink-secondary">Showing {list.items.length} of {node.findings}; open the agent in the graph for the rest.</p>
      )}
    </div>
  );
}

function Evals({ coverage }: { coverage: NonNullable<ArchitectureNode["agent"]>["eval_coverage"] }) {
  if (!coverage?.assessed) {
    return <p className="text-sm text-ink-secondary">Eval coverage was not assessed in this scan; the project files were not fully searched for eval suites.</p>;
  }
  const suites = coverage.suites.map(parseEvalSuite).filter((suite): suite is EvalSuiteRef => suite !== null);
  return (
    <div className="space-y-2">
      <p className="text-sm text-foreground">
        {coverage.safety_suites > 0
          ? `${coverage.safety_suites} linked safety ${coverage.safety_suites === 1 ? "eval" : "evals"}`
          : "No safety or red-team eval linked to this agent in the scanned project files."}
      </p>
      <EvalSuiteList suites={suites} empty="No eval in the scanned files targets this agent." />
    </div>
  );
}

function AgentBody({ node, model, scanId }: { node: ArchitectureNode; model: ArchitectureModel; scanId: string }) {
  const agent = node.agent!;
  const labels = new Map(model.nodes.map(item => [item.id, item.label]));
  const outgoing = model.edges.filter(edge => edge.source === node.id && edge.kind !== "unresolved");
  const reach = Object.entries(agent.security.reach);
  return <>
    <Section title="Risk">
      <p className="text-sm text-foreground">Risk score {agent.security.risk_score.toFixed(1)}{agent.security.severity ? ` · severity ${agent.security.severity}` : ""}</p>
      {reach.length > 0 && <p className="text-sm text-ink-secondary">Reaches {reach.map(([relationship, count]) => `${count} via ${relationship.replaceAll("_", " ")}`).join(", ")}</p>}
    </Section>
    <Section title="Findings"><Findings node={node} scanId={scanId} /></Section>
    <Section title="Evals"><Evals coverage={agent.eval_coverage} /></Section>
    <Section title="Model references"><Names items={agent.model_refs} empty="No literal model name in source." /></Section>
    <Section title="Tools"><Names items={agent.tools} empty="No tools declared." /></Section>
    <Section title="Credential references"><Names items={agent.credential_refs} empty="No credential names referenced." /></Section>
    {(outgoing.length > 0 || node.returnsTo.length > 0 || node.peers.length > 0) && (
      <Section title="Declared routes">
        <ul className="space-y-0.5 text-sm text-ink-secondary">
          {outgoing.map(edge => <RouteLine key={edge.id} kind="next" text={`${labels.get(edge.target)} · ${edge.description}`} />)}
          {node.returnsTo.map(item => <RouteLine key={`r-${item.id}-${item.kind}`} kind="returns" text={`Returns to ${item.label} · ${FLOW_KIND_LABEL[item.kind]}`} />)}
          {node.peers.map(item => <RouteLine key={`p-${item.id}`} kind="peer" text={`Shares a server with ${item.label}`} />)}
        </ul>
        {agent.dynamic_edges && <p className="text-xs text-ink-secondary">Some routes of this agent are decided at runtime.</p>}
      </Section>
    )}
    <Section title="Source">
      <p className="font-mono text-[13px] text-foreground">{agent.file_path}{agent.line_number ? `:${agent.line_number}` : ""}</p>
    </Section>
    <Link className={`${LINK} text-sm`} href={buildFindingAssetHref({ nodeId: node.id, findingId: "", ...(scanId ? { scanId } : {}) })}>Investigate in graph</Link>
  </>;
}

function OtherBody({ node, onExpand }: { node: ArchitectureNode; onExpand: (id: string) => void }) {
  if (node.kind === "stub") {
    return (
      <Section title="Routes the scan could not resolve">
        <ul className="space-y-2 text-sm">
          {node.unresolved!.map((route, index) => (
            <li key={index} className="rounded-lg border border-outline px-3 py-2">
              <p className="font-mono text-[13px] text-foreground">{route.evidence || "Route"}{route.line_number ? ` · line ${route.line_number}` : ""}</p>
              <p className="text-ink-secondary">{route.reason}</p>
            </li>
          ))}
        </ul>
      </Section>
    );
  }
  if (node.kind === "group") {
    return <button type="button" onClick={() => onExpand(node.id)} className={`${LINK} text-sm`}>Expand {node.label}</button>;
  }
  return <p className="text-sm text-ink-secondary">The declared finish of {node.label.replace(/^End of /, "") || "the harness"}.</p>;
}

export function ArchitectureDetail({ node, model, scanId, onClose, onExpand }: {
  node: ArchitectureNode | null; model: ArchitectureModel; scanId: string; onClose: () => void; onExpand: (id: string) => void;
}) {
  return (
    <Drawer open={node !== null} onClose={onClose} size="lg" closeLabel="Close agent details" ariaLabel={node ? `${node.label} details` : "Agent details"}
      eyebrow={node?.agent ? frameworkLabel(node.agent.framework) : undefined}
      title={node?.label ?? ""} subtitle={node ? `${node.subtitle}${node.entry ? " · Entry" : ""}${node.agent ? ` · layer ${node.layer}` : ""}` : undefined}>
      {node && <div className="space-y-5">{node.agent ? <AgentBody node={node} model={model} scanId={scanId} /> : <OtherBody node={node} onExpand={onExpand} />}</div>}
    </Drawer>
  );
}
