"use client";

import { useState, type CSSProperties } from "react";
import type { AgentSource } from "@/lib/agent-source";
import { providerMarkBasis } from "@/lib/provider-basis";

/**
 * The provider mark on a graph glyph or scope label. A canvas-coloured cut-out
 * border separates it from the node ring; the inner outline keeps ≥3:1 against
 * the canvas in both themes and turns dashed when the provider was inherited.
 */
export function GraphProviderMark({ source, attributes, className = "", style }: {
  source: AgentSource;
  attributes?: Record<string, unknown> | undefined;
  className?: string;
  style?: CSSProperties;
}) {
  const [failedSrc, setFailedSrc] = useState<string | null>(null);
  const basis = providerMarkBasis(source, attributes);
  return (
    <span role="img" aria-label={basis.title} title={basis.title}
      data-agent-source={source.id} data-agent-source-badge="true" data-graph-source-badge="true"
      data-provider-basis={basis.inherited ? "inherited" : "declared"}
      className={`graph-provider-mark ${source.darkMark ? "graph-provider-mark-dark" : source.mono ? "graph-provider-mark-mono" : ""} ${className}`} style={style}>
      {source.src && !source.badgeMonogram && source.src !== failedSrc
        // eslint-disable-next-line @next/next/no-img-element
        ? <img src={source.src} alt="" className={`graph-provider-mark-glyph graph-provider-mark-glyph-${source.id}`} onError={() => setFailedSrc(source.src)} />
        : <span className="text-[0.4em] font-semibold leading-none">{source.monogram}</span>}
    </span>
  );
}
