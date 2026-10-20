"use client";

import { useState, type ReactNode } from "react";
import { DetailFrame } from "./lineage-detail/frame";
import { OverviewDetails } from "./lineage-detail/overview";
import { relationshipSection, impactSection, attributesSection } from "./lineage-detail/sections";
import type { LineageDetailProps, TabId } from "./lineage-detail/types";

export function LineageDetailPanel(props: LineageDetailProps) {
  const { data, relationshipSlot, headerSlot } = props;
  const typeSection = <OverviewDetails {...props} />;
  const relationshipsSection = relationshipSection(data, relationshipSlot);
  const impact = impactSection(data);
  const attributes = attributesSection(data);
  const tabs: { id: TabId; label: string; content: ReactNode }[] = [
    { id: "overview", label: "Overview", content: data.nodeType === "misconfiguration" || data.nodeType === "vulnerability" ? <>{headerSlot}{typeSection}</> : <>{typeSection}{headerSlot}</> },
    ...(relationshipsSection
      ? [
          {
            id: "relationships" as const,
            label: "Relationships",
            content: relationshipsSection,
          },
        ]
      : []),
    ...(impact
      ? [{ id: "impact" as const, label: "Impact", content: impact }]
      : []),
    ...(attributes
      ? [
          {
            id: "attributes" as const,
            label: "Attributes",
            content: attributes,
          },
        ]
      : []),
  ];

  const [activeTab, setActiveTab] = useState<TabId>("overview");
  const activeId = tabs.some((tab) => tab.id === activeTab)
    ? activeTab
    : (tabs[0]?.id ?? "overview");
  const activeContent =
    tabs.find((tab) => tab.id === activeId)?.content ?? typeSection;

  const tabBar = tabs.length > 1 ? (
    <div
      role="tablist"
      aria-label="Node detail sections"
      className="flex shrink-0 gap-1 overflow-x-auto border-b border-outline px-4"
    >
      {tabs.map((tab) => {
        const selected = tab.id === activeId;
        return (
          <button
            key={tab.id}
            type="button"
            role="tab"
            aria-selected={selected}
            data-testid={`graph-drawer-tab-${tab.id}`}
            onClick={() => setActiveTab(tab.id)}
            className={`-mb-px border-b-2 px-2.5 py-1.5 text-xs font-medium transition-colors ${
              selected
                ? "border-[color:var(--accent-border)] text-foreground"
                : "border-transparent text-ink-tertiary hover:text-ink-secondary"
            }`}
          >
            {tab.label}
          </button>
        );
      })}
    </div>
  ) : null;

  return <DetailFrame {...props} tabBar={tabBar} activeId={activeId} activeContent={activeContent} />;
}
