"use client";

import { useState, type CSSProperties } from "react";
import { Server } from "lucide-react";
import { ASSET_BASE } from "@/lib/asset-base";

/** Exact bundled protocol mark; hosting/vendor identity remains a separate badge. */
export function McpGlyph({ className, style }: { className?: string; style?: CSSProperties }) {
  const [failed, setFailed] = useState(false);
  if (failed) return <Server aria-hidden="true" className={className} style={style} />;
  // eslint-disable-next-line @next/next/no-img-element
  return <img src={`${ASSET_BASE}/logos/mcp.svg`} alt="" aria-hidden="true" data-protocol-mark="mcp"
    className={className} style={style} onError={() => setFailed(true)} />;
}
