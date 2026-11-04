import type { CSSProperties } from "react";

type GlyphProps = { className?: string; style?: CSSProperties };

/** Storage bucket silhouette, distinct from a database or an archive box. */
export function BucketGlyph(props: GlyphProps) {
  return <svg {...props} data-asset-glyph="bucket" aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <ellipse cx="12" cy="5" rx="8" ry="3" />
    <path d="M4 5l2 14c.4 1.4 2.8 2 6 2s5.6-.6 6-2l2-14M8 12c2.6 1.1 5.4 1.1 8 0" />
  </svg>;
}

/** A virtual machine is a compute instance, not a physical CPU chip. */
export function VirtualMachineGlyph(props: GlyphProps) {
  return <svg {...props} data-asset-glyph="virtual-machine" aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <rect x="8" y="8" width="13" height="13" rx="2" />
    <path d="M5 16H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h11a1 1 0 0 1 1 1v1M12 17h5" />
  </svg>;
}
