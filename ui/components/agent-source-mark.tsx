"use client";

import { useState, type CSSProperties } from "react";
import { Bot } from "lucide-react";
import type { AgentSource } from "@/lib/agent-source";
import type { EntityIcon } from "@/lib/entity-icons";

/** Local, accessible source badge shared by glyph overlays and graph nodes. */
export function SourceBadge({ source, className = "", style, graph = false }: {
  source: AgentSource;
  className?: string;
  style?: CSSProperties;
  graph?: boolean;
}) {
  const [failedSrc, setFailedSrc] = useState<string | null>(null);
  return (
    <span role="img" aria-label={`Source: ${source.label}`} title={`Source: ${source.label}`}
      data-agent-source={source.id} data-agent-source-badge="true"
      data-graph-source-badge={graph ? "true" : undefined}
      className={`inline-flex items-center justify-center overflow-hidden rounded-full border border-outline p-0.5 ${className}`}
      style={{ background: source.darkMark ? "#202123" : "#ffffff", color: "#202123", ...style }}>
      {source.src && source.src !== failedSrc
        // eslint-disable-next-line @next/next/no-img-element
        ? <img src={source.src} alt="" className={`h-full w-full object-contain ${source.id === "openai" ? "scale-[1.8]" : ""}`} onError={() => setFailedSrc(source.src)} />
        : <span className="text-[0.6em] font-semibold leading-none" style={{ color: source.darkMark ? "#ffffff" : "#202123" }}>{source.monogram}</span>}
    </span>
  );
}

/** The entity glyph stays primary; a local vendor badge supplies a secondary cue. */
export function AgentSourceMark({ source, className = "", style, icon: Icon = Bot }: {
  source: AgentSource | null;
  className?: string;
  style?: CSSProperties;
  icon?: EntityIcon | undefined;
}) {
  return (
    <span className={`relative inline-flex shrink-0 items-center justify-center ${className}`} style={style}>
      <Icon aria-hidden="true" className="h-full w-full" />
      {source && <SourceBadge source={source} className="absolute -bottom-0.5 -right-0.5 h-1/2 min-h-2.5 w-1/2 min-w-2.5" />}
    </span>
  );
}
