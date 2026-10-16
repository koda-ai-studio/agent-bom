"use client";

import { useState, type CSSProperties } from "react";
import { Bot } from "lucide-react";
import type { AgentSource } from "@/lib/agent-source";

/** Local source marks keep dimensions stable and never fetch vendor endpoints. */
export function AgentSourceMark({ source, className = "", style }: {
  source: AgentSource | null;
  className?: string;
  style?: CSSProperties;
}) {
  const [failedSrc, setFailedSrc] = useState<string | null>(null);
  if (!source) return <Bot aria-hidden="true" className={className} style={style} />;
  return (
    <span role="img" aria-label={`Source: ${source.label}`} title={`Source: ${source.label}`}
      data-agent-source={source.id}
      className={`inline-flex shrink-0 items-center justify-center overflow-hidden rounded-full p-1 ${className}`}
      style={{ background: source.darkMark ? "#202123" : "#ffffff", color: "#202123", ...style }}>
      {source.src && source.src !== failedSrc
        // eslint-disable-next-line @next/next/no-img-element
        ? <img src={source.src} alt="" className={`h-full w-full object-contain ${source.id === "openai" ? "scale-[1.8]" : ""}`} onError={() => setFailedSrc(source.src)} />
        : <span className="text-[0.6em] font-semibold leading-none" style={{ color: source.darkMark ? "#ffffff" : "#202123" }}>{source.monogram}</span>}
    </span>
  );
}
