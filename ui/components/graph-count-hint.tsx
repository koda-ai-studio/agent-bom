"use client";

import { cloneElement, useId, useLayoutEffect, useRef, useState, type ReactElement } from "react";
import { createPortal } from "react-dom";

/** Counts disclose meaning without covering another entity's name or glyph. */
export function GraphCountHint({ children, text }: { children: ReactElement<{ "aria-describedby"?: string | undefined }>; text: string }) {
  const id = useId();
  const [open, setOpen] = useState(false);
  const [at, setAt] = useState({ left: -1000, top: -1000 });
  const anchor = useRef<HTMLSpanElement>(null);
  const hint = useRef<HTMLSpanElement>(null);
  useLayoutEffect(() => {
    if (!open || !anchor.current || !hint.current) return;
    const a = anchor.current.getBoundingClientRect();
    const h = hint.current.getBoundingClientRect();
    const canvas = anchor.current.closest(".react-flow");
    const obstacles = [...(canvas?.querySelectorAll("[data-graph-entity] > *") ?? [])]
      .map(el => el.getBoundingClientRect()).filter(r => r.width && r.height);
    const c = canvas?.getBoundingClientRect();
    const candidates = [
      { left: a.left + a.width / 2 - h.width / 2, top: a.top - h.height - 10 },
      { left: a.left - h.width - 12, top: a.top + a.height / 2 - h.height / 2 },
      { left: a.right + 12, top: a.top + a.height / 2 - h.height / 2 },
      { left: a.left + a.width / 2 - h.width / 2, top: a.bottom + 10 },
      { left: a.left - h.width - 40, top: a.top - h.height - 24 },
      { left: a.right + 40, top: a.top - h.height - 24 },
      { left: a.left - h.width - 40, top: a.bottom + 24 },
      { left: a.right + 40, top: a.bottom + 24 },
      ...(c ? [{ left: c.left + 16, top: c.top + 16 }, { left: c.right - h.width - 16, top: c.top + 16 }] : []),
    ].map(p => ({ left: Math.max(8, Math.min(innerWidth - h.width - 8, p.left)), top: Math.max(8, Math.min(innerHeight - h.height - 8, p.top)) }));
    const overlaps = (p: typeof at) => obstacles.filter(r => p.left < r.right && p.left + h.width > r.left && p.top < r.bottom && p.top + h.height > r.top).length;
    candidates.sort((a, b) => overlaps(a) - overlaps(b));
    setAt(candidates[0]!);
  }, [open, text]);
  return <span ref={anchor} className="relative inline-flex" onMouseEnter={() => setOpen(true)} onMouseLeave={() => setOpen(false)}
    onFocus={() => setOpen(true)} onBlur={() => setOpen(false)} onKeyDown={event => { if (event.key === "Escape") setOpen(false); }}>
    {cloneElement(children, { "aria-describedby": [children.props["aria-describedby"], open ? id : undefined].filter(Boolean).join(" ") || undefined })}
    {open && createPortal(<span ref={hint} id={id} role="tooltip"
      className="pointer-events-none fixed z-[100] w-64 max-w-[calc(100vw-1rem)] rounded-lg border border-outline-strong bg-surface-elevated px-3 py-2 text-xs font-normal leading-relaxed text-foreground shadow-lg"
      style={at}>{text}</span>, document.body)}
  </span>;
}
