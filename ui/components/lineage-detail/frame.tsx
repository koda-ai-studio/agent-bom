"use client";
import { useEffect, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { ChevronLeft, ChevronRight, X, FolderGit2 } from "lucide-react";
import { Drawer } from "@/components/drawer";
import { AgentSourceMark } from "@/components/agent-source-mark";
import { entitySource } from "@/lib/agent-source";
import { nodeGlyph } from "@/lib/graph-container-kind";
import { assetSubtypeLabel } from "@/lib/asset-icon-registry";
import { graphRepositoryContext } from "@/lib/graph-repository-context";
import { NODE_LABELS } from "@/lib/entity-labels";
import { useDrawerWidth } from "@/lib/use-drawer-width";
import type { LineageNodeData } from "../lineage-nodes";
import type { LineageDetailProps, TabId } from "./types";

const TYPE_BORDER: Record<LineageNodeData["nodeType"], string> = {
  provider: "border-outline",
  agent: "border-emerald-700",
  org: "border-teal-800",
  account: "border-teal-700",
  user: "border-emerald-700",
  group: "border-fuchsia-700",
  role: "border-orange-700",
  policy: "border-amber-700",
  serviceAccount: "border-amber-700",
  servicePrincipal: "border-teal-700",
  federatedIdentity: "border-cyan-700",
  environment: "border-teal-700",
  fleet: "border-cyan-700",
  cluster: "border-sky-700",
  server: "border-blue-700",
  sharedServer: "border-cyan-700",
  package: "border-outline",
  vulnerability: "border-red-700",
  misconfiguration: "border-orange-700",
  credential: "border-amber-700",
  tool: "border-purple-700",
  model: "border-violet-700",
  framework: "border-cyan-700",
  dataset: "border-cyan-700",
  container: "border-indigo-700",
  cloudResource: "border-sky-700",
  managedIdentity: "border-cyan-700",
  accessGrant: "border-yellow-700",
  accessPolicy: "border-amber-700",
  driftIncident: "border-orange-700",
  dataStore: "border-sky-700",
  directory: "border-teal-700",
  sourceFile: "border-cyan-700",
  configFile: "border-orange-700",
  codeModule: "border-cyan-700",
  ciJob: "border-purple-700",
  apiGateway: "border-blue-700",
  toolCall: "border-purple-700",
  blueprint: "border-indigo-700",
};

type FrameProps = LineageDetailProps & { tabBar: ReactNode; activeId: TabId; activeContent: ReactNode };

function useFrameState(variant: LineageDetailProps["variant"]) {
  const resize = useDrawerWidth();
  const isOverlay = variant === "overlay";
  const isDocked = variant === "docked";
  const [dockedCollapsed, setDockedCollapsed] = useState(false);
  const [mobileViewport, setMobileViewport] = useState(false);
  useEffect(() => {
    if (typeof window.matchMedia !== "function") return;
    const query = window.matchMedia("(max-width: 639px)");
    const update = () => setMobileViewport(query.matches);
    update();
    query.addEventListener("change", update);
    return () => query.removeEventListener("change", update);
  }, []);
  const mobileDialog = mobileViewport && (isOverlay || isDocked);
  useEffect(() => {
    if (!mobileDialog) return;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => { document.body.style.overflow = previousOverflow; };
  }, [mobileDialog]);

  return { ...resize, isOverlay, isDocked, dockedCollapsed, setDockedCollapsed, mobileDialog };
}

function DetailHeader({ data, onClose, isDocked, setDockedCollapsed }: Pick<FrameProps, "data" | "onClose"> & Pick<ReturnType<typeof useFrameState>, "isDocked" | "setDockedCollapsed">) {
  const repository = graphRepositoryContext(data);
  const Icon = repository ? FolderGit2 : nodeGlyph(data.nodeType, data.attributes, data.entityType, data.dimensions?.cloud_provider);
  const brand = entitySource(data);
  const typeLabel = repository ? "Repository" : assetSubtypeLabel({ entityType: data.entityType, nodeType: data.nodeType, attributes: data.attributes, provider: data.dimensions?.cloud_provider }) ?? (data.nodeType === "server" ? "MCP Server" : data.nodeType === "sharedServer" ? "Shared MCP Server" : NODE_LABELS[data.nodeType]);
  return (<>
      {/* Header — always visible */}
      <div className="flex shrink-0 items-start justify-between gap-3 px-4 pt-4 pb-3">
        <div className="min-w-0">
          <span className="text-[10px] uppercase tracking-wider text-ink-tertiary">
            {typeLabel}
          </span>
          <div className="mt-2 flex items-start gap-3">
            <span className="rounded-full border border-outline bg-surface-muted p-2" style={brand ? { borderColor: brand.accent } : undefined}>
              {brand || repository ? <AgentSourceMark source={repository?.source ?? brand} icon={Icon} className="h-5 w-5 text-ink-secondary" /> : <Icon aria-hidden="true" className="h-5 w-5 shrink-0 text-ink-secondary" />}
            </span>
            <h3 className="min-w-0 self-center break-words text-base font-semibold leading-5 text-foreground [overflow-wrap:anywhere]">
              {data.label}
            </h3>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-1">
        {isDocked && <button type="button" aria-label="Collapse details" title="Collapse node details" onClick={() => setDockedCollapsed(true)}
          className="rounded-md p-1 text-ink-tertiary transition-colors hover:bg-surface-muted hover:text-foreground focus-visible:outline-2 focus-visible:outline-emerald-500">
          <ChevronRight className="h-4 w-4" aria-hidden="true" />
        </button>}
        <button
          onClick={onClose}
          aria-label="Close"
          className="shrink-0 p-1 text-ink-tertiary hover:text-ink-secondary transition-colors"
        >
          <X className="w-4 h-4" />
        </button>
        </div>
      </div>

  </>);
}

function MobileDetailFrame({ data, onClose, footerSlot, tabBar, activeId, activeContent }: FrameProps) {
  const repository = graphRepositoryContext(data);
  const Icon = repository ? FolderGit2 : nodeGlyph(data.nodeType, data.attributes, data.entityType, data.dimensions?.cloud_provider);
  const brand = entitySource(data);
  const typeLabel = repository ? "Repository" : assetSubtypeLabel({ entityType: data.entityType, nodeType: data.nodeType, attributes: data.attributes, provider: data.dimensions?.cloud_provider }) ?? (data.nodeType === "server" ? "MCP Server" : data.nodeType === "sharedServer" ? "Shared MCP Server" : NODE_LABELS[data.nodeType]);
    return createPortal(
      <div className="fixed inset-0 z-[80]" data-testid="graph-entity-drawer">
        <Drawer open onClose={onClose} title={data.label} backdropLabel="Dismiss graph details"
          eyebrow={typeLabel} size="none" resizable={false}
          headerAside={repository || brand ? <AgentSourceMark source={repository?.source ?? brand} icon={Icon} className="h-9 w-9" /> : undefined}
          bodyClassName="!p-0 flex flex-col" footer={footerSlot}>
          {tabBar}
          <div role="tabpanel" data-testid={`graph-drawer-panel-${activeId}`}
            className="min-h-0 flex-1 space-y-4 overflow-y-auto p-4">
            {activeContent}
          </div>
        </Drawer>
      </div>, document.body,
    );
}

function CollapsedDetailFrame({ data, setDockedCollapsed }: Pick<FrameProps, "data"> & Pick<ReturnType<typeof useFrameState>, "setDockedCollapsed">) {
    return (
      <aside className="flex h-full min-h-0 w-12 shrink-0 flex-col items-center gap-3 border-l border-outline bg-background/95 py-3" data-testid="graph-entity-drawer-collapsed">
        <button type="button" aria-label="Show node details" title={`Show details for ${data.label}`} onClick={() => setDockedCollapsed(false)}
          className="rounded-md p-2 text-ink-secondary hover:bg-surface-muted hover:text-foreground focus-visible:outline-2 focus-visible:outline-emerald-500">
          <ChevronLeft className="h-4 w-4" aria-hidden="true" />
        </button>
        <span className="max-h-[65%] overflow-hidden text-ellipsis text-xs text-ink-secondary [writing-mode:vertical-rl]" title={data.label}>{data.label}</span>
      </aside>
    );
}

export function DetailFrame({ data, onClose, variant = "overlay", footerSlot, tabBar, activeId, activeContent }: FrameProps) {
  const state = useFrameState(variant);
  const { width, minWidth, maxWidth, onHandlePointerDown, onHandleKeyDown, isOverlay, isDocked, dockedCollapsed, setDockedCollapsed, mobileDialog } = state;

  if (mobileDialog) return <MobileDetailFrame data={data} onClose={onClose} footerSlot={footerSlot} tabBar={tabBar} activeId={activeId} activeContent={activeContent} />;
  if (isDocked && dockedCollapsed) return <CollapsedDetailFrame data={data} setDockedCollapsed={setDockedCollapsed} />;

  const shellClass = isOverlay
    ? `absolute right-0 top-0 bottom-0 flex max-w-full flex-col bg-background border-l ${TYPE_BORDER[data.nodeType]} z-50`
    : isDocked
      ? `relative flex h-full min-h-0 min-w-[18rem] max-w-[36%] shrink-0 flex-col border-l ${TYPE_BORDER[data.nodeType]} bg-background/95`
      : `relative flex w-full max-w-none flex-col border ${TYPE_BORDER[data.nodeType]} bg-background/95 rounded-xl`;

  return (
    <div
      className={shellClass}
      style={isOverlay || isDocked ? { width } : undefined}
      data-testid="graph-entity-drawer"
    >
      {(isOverlay || isDocked) && (
        <div
          role="separator"
          aria-label="Resize drawer"
          aria-orientation="vertical"
          aria-valuenow={width}
          aria-valuemin={minWidth}
          aria-valuemax={maxWidth}
          aria-valuetext={`${width} pixels`}
          tabIndex={0}
          onKeyDown={onHandleKeyDown}
          onPointerDown={onHandlePointerDown}
          title="Drag to resize"
          className="absolute inset-y-0 left-0 z-10 w-1.5 cursor-col-resize bg-transparent transition-colors hover:bg-[color:var(--accent-border)] focus:bg-[color:var(--accent-border)] focus:outline-none"
        />
      )}

      <DetailHeader data={data} onClose={onClose} isDocked={isDocked} setDockedCollapsed={setDockedCollapsed} />

      {tabBar}

      {/* Active tab content — scrolls independently in overlay mode */}
      <div
        role="tabpanel"
        data-testid={`graph-drawer-panel-${activeId}`}
        className={`min-w-0 space-y-4 p-4 ${
          isOverlay || isDocked ? "min-h-0 flex-1 overflow-y-auto overscroll-contain" : ""
        }`}
      >
        {activeContent}
      </div>

      {/* Action footer — always visible */}
      {footerSlot ? <div className="shrink-0 px-4 pb-4">{footerSlot}</div> : null}
    </div>
  );
}
