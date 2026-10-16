"use client";

import { useState, type CSSProperties } from "react";
import { Bot } from "lucide-react";
import type { AgentSource } from "@/lib/agent-source";

/** The agent glyph stays primary; a local vendor badge supplies a secondary cue. */
export function AgentSourceMark({ source, className = "", style }: {
  source: AgentSource | null;
  className?: string;
  style?: CSSProperties;
}) {
  const [failedSrc, setFailedSrc] = useState<string | null>(null);
  return (
    <span className={`relative inline-flex shrink-0 items-center justify-center ${className}`} style={style}>
      <Bot aria-hidden="true" className="h-full w-full" />
      {source && (
    <span role="img" aria-label={`Source: ${source.label}`} title={`Source: ${source.label}`}
      data-agent-source={source.id} data-agent-source-badge="true"
      className="absolute -bottom-0.5 -right-0.5 inline-flex h-1/2 min-h-2.5 w-1/2 min-w-2.5 items-center justify-center overflow-hidden rounded-full border border-outline p-0.5"
      style={{ background: source.darkMark ? "#202123" : "#ffffff", color: "#202123" }}>
      {source.src && source.src !== failedSrc
        // eslint-disable-next-line @next/next/no-img-element
        ? <img src={source.src} alt="" className={`h-full w-full object-contain ${source.id === "openai" ? "scale-[1.8]" : ""}`} onError={() => setFailedSrc(source.src)} />
        : <span className="text-[0.6em] font-semibold leading-none" style={{ color: source.darkMark ? "#ffffff" : "#202123" }}>{source.monogram}</span>}
    </span>
      )}
    </span>
  );
}
