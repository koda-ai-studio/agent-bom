"use client";

/** Focus, dimming and cluster-pill styles for lineage canvases. */
export function GraphPulseStyles() {
  return (
    <style jsx global>{`
      .node-critical-pulse .graph-entity-glyph,
      .node-critical-pulse > div:not([data-graph-entity]) {
        box-shadow: 0 0 6px rgba(239, 68, 68, 0.28);
      }

      /* Focus-mode (#2257). Hovering or pinning a node fires CSS classes
         on the React Flow node wrapper so non-connected nodes fade out
         and focused cards get a crisp outline following their shape. The transition is
         short enough to feel responsive but long enough to read as a
         deliberate dim, not a flicker. */
      .lineage-node-dim {
        opacity: 0.15;
        transition: opacity 0.2s ease;
      }
      .lineage-node-focus {
        z-index: 5;
      }
      .lineage-node-focus .graph-entity-glyph,
      .lineage-node-focus > div:not([data-graph-entity]) {
        outline: 2px solid var(--accent);
        outline-offset: 3px;
      }

      /* Sibling-aggregation cluster pill pulses subtly to suggest
         "click me to expand". Honors prefers-reduced-motion. */
      @keyframes cluster-pill-pulse {
        0%,
        100% {
          box-shadow: 0 0 6px rgba(56, 189, 248, 0.35);
        }
        50% {
          box-shadow: 0 0 14px rgba(56, 189, 248, 0.65);
        }
      }
      .cluster-pill-pulse {
        animation: none;
        box-shadow: 0 0 8px rgba(56, 189, 248, 0.32);
      }
      @media (prefers-reduced-motion: reduce) {
        .cluster-pill-pulse {
          animation: none;
          box-shadow: 0 0 8px rgba(56, 189, 248, 0.45);
        }
      }
    `}</style>
  );
}

