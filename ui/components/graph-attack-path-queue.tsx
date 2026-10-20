"use client";

import { AttackPathCard } from "@/components/attack-path-card";
import { AttackPathTechniqueChain } from "@/components/attack-path-technique-chain";
import { PathStat, PathTagList } from "@/components/graph-path-stats";
import { attackPathKey, toAttackCardNodes } from "@/lib/attack-paths";
import type { AttackPath, UnifiedNode } from "@/lib/graph-schema";

/** The ranked attack-path queue behind Advanced controls, with the selected path's evidence stats. */
export function GraphAttackPathQueue({ paths, selected, selectedKey, nodeById, captureMode, visibleHopCount, evidenceHopCount, onSelect }: {
  paths: AttackPath[];
  selected: AttackPath | null;
  selectedKey: string | null;
  nodeById: Map<string, UnifiedNode>;
  captureMode: boolean;
  visibleHopCount: number;
  evidenceHopCount: number;
  onSelect: (key: string | null) => void;
}) {
  if (paths.length === 0) return null;
  return (
          <details className="mt-3 rounded-2xl border border-outline bg-background/60 p-3 group">
            <summary className="flex cursor-pointer list-none flex-wrap items-center justify-between gap-2 [&::-webkit-details-marker]:hidden">
              <div>
                <p className="text-xs uppercase tracking-[0.24em] text-orange-400">
                  Attack paths
                </p>
                <p className="mt-1 text-xs text-ink-tertiary">
                  {paths.length} ranked path
                  {paths.length === 1 ? "" : "s"} available for focused
                  investigation.
                </p>
              </div>
              <span className="text-xs uppercase tracking-[0.18em] text-ink-tertiary group-open:hidden">
                show queue
              </span>
              <span className="hidden text-xs uppercase tracking-[0.18em] text-ink-tertiary group-open:inline">
                hide queue
              </span>
            </summary>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <p className="mt-3 text-xs text-ink-tertiary">
                  Focus the current graph on a precomputed exploit chain in this
                  filtered snapshot page.
                </p>
              </div>
              {selected && (
                <button
                  type="button"
                  onClick={() => {
                    onSelect(null);
                  }}
                  className="graph-page-secondary-action"
                >
                  Clear path focus
                </button>
              )}
            </div>

            <div className="mt-3 flex gap-3 overflow-x-auto pb-1">
              {paths.map((path) => {
                const key = attackPathKey(path);
                const pathNodes = toAttackCardNodes(path, nodeById);
                if (pathNodes.length === 0) return null;
                const isActive = selectedKey === key;
                return (
                  <div
                    key={key}
                    className={`min-w-0 sm:min-w-[360px] rounded-2xl transition ${isActive ? "ring-2 ring-orange-400/70 ring-offset-2 ring-offset-[var(--background)]" : ""}`}
                  >
                    <AttackPathCard
                      nodes={pathNodes}
                      riskScore={path.composite_risk}
                      captureMode={captureMode}
                      onClick={() => {
                        const clearing = selectedKey === key;
                        onSelect(clearing ? null : key);
                      }}
                    />
                  </div>
                );
              })}
            </div>

            {selected && (
              <div className="mt-3 grid gap-2 lg:grid-cols-4">
                <PathStat
                  label="Composite risk"
                  value={selected.composite_risk.toFixed(1)}
                  tone="red"
                />
                <PathStat
                  label="Hop count"
                  value={
                    visibleHopCount === evidenceHopCount
                      ? `${evidenceHopCount} evidence`
                      : `${evidenceHopCount} evidence · ${visibleHopCount} visible`
                  }
                />
                <PathStat
                  label="Credential exposure"
                  value={
                    selected.credential_exposure.length > 0
                      ? selected.credential_exposure.length.toString()
                      : "none"
                  }
                  tone={
                    selected.credential_exposure.length > 0
                      ? "amber"
                      : "zinc"
                  }
                />
                <PathStat
                  label="Tool exposure"
                  value={
                    selected.tool_exposure.length > 0
                      ? selected.tool_exposure.length.toString()
                      : "none"
                  }
                  tone={
                    selected.tool_exposure.length > 0
                      ? "blue"
                      : "zinc"
                  }
                />
                <PathTagList
                  label="Summary"
                  tags={[selected.summary || "No summary provided"]}
                  wide
                />
                <AttackPathTechniqueChain path={selected} />
                {selected.vuln_ids.length > 0 && (
                  <PathTagList
                    label="Findings"
                    tags={selected.vuln_ids}
                  />
                )}
                {selected.credential_exposure.length > 0 && (
                  <PathTagList
                    label="Credentials"
                    tags={selected.credential_exposure}
                  />
                )}
                {selected.tool_exposure.length > 0 && (
                  <PathTagList
                    label="Tools"
                    tags={selected.tool_exposure}
                  />
                )}
              </div>
            )}
          </details>
  );
}
