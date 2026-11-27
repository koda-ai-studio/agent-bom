"use client";

import { useEffect, useRef, type ReactNode } from "react";

/** Keep keyboard inspection on the same edge when node measurement replaces its SVG. */
export function GraphEdgeFocusBoundary({ children }: { children: ReactNode }) {
  const host = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const element = host.current!;
    let focusedId: string | undefined;
    const remember = (event: FocusEvent) => {
      const edge = event.target instanceof Element ? event.target.closest<SVGGElement>(".react-flow__edge") : null;
      focusedId = edge && element.contains(edge) ? edge.dataset.id : undefined;
    };
    const clear = () => { focusedId = undefined; };
    const escape = (event: KeyboardEvent) => { if (event.key === "Escape") clear(); };
    const observer = new MutationObserver(() => {
      if (!focusedId || document.activeElement !== document.body || !element.isConnected) return;
      element.querySelector<SVGGElement>(`.react-flow__edge[data-id="${CSS.escape(focusedId)}"]`)?.focus({ preventScroll: true });
    });
    document.addEventListener("focusin", remember);
    document.addEventListener("pointerdown", clear, true);
    document.addEventListener("keydown", escape, true);
    observer.observe(element, { childList: true, subtree: true });
    return () => {
      observer.disconnect();
      document.removeEventListener("focusin", remember);
      document.removeEventListener("pointerdown", clear, true);
      document.removeEventListener("keydown", escape, true);
    };
  }, []);
  return <div ref={host} className="contents">{children}</div>;
}
