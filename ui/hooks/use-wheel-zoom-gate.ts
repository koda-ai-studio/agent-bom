"use client";

import { createElement, useCallback, useEffect, useRef, useState, type ReactElement, type WheelEvent } from "react";

const HINT_MS = 2_200;

/** Graph canvases follow the map convention: a plain wheel scrolls the page; zoom needs a modifier or a click. */
export function wheelZoomHintText(platform: string = typeof navigator === "undefined" ? "" : navigator.platform): string {
  const modifier = /mac|iphone|ipad/i.test(platform) ? "⌘" : "Ctrl";
  return `Use ${modifier} + scroll to zoom, or click the graph first`;
}

export function useWheelZoomGate() {
  const [modifierHeld, setModifierHeld] = useState(false);
  const [captured, setCaptured] = useState(false);
  const [hintVisible, setHintVisible] = useState(false);
  const hinted = useRef(false);
  const hintTimer = useRef<number | null>(null);
  const armed = modifierHeld || captured;

  useEffect(() => {
    const isModifier = (event: KeyboardEvent) => event.key === "Control" || event.key === "Meta";
    const down = (event: KeyboardEvent) => { if (isModifier(event)) setModifierHeld(true); };
    const up = (event: KeyboardEvent) => { if (isModifier(event)) setModifierHeld(false); };
    const clear = () => setModifierHeld(false);
    window.addEventListener("keydown", down);
    window.addEventListener("keyup", up);
    window.addEventListener("blur", clear);
    return () => {
      window.removeEventListener("keydown", down);
      window.removeEventListener("keyup", up);
      window.removeEventListener("blur", clear);
      if (hintTimer.current !== null) window.clearTimeout(hintTimer.current);
    };
  }, []);

  const onWheel = useCallback((event: WheelEvent<HTMLElement>) => {
    if (armed || event.ctrlKey || event.metaKey || hinted.current) return;
    hinted.current = true;
    setHintVisible(true);
    hintTimer.current = window.setTimeout(() => setHintVisible(false), HINT_MS);
  }, [armed]);
  const onPointerDown = useCallback(() => setCaptured(true), []);
  const onPointerLeave = useCallback(() => setCaptured(false), []);

  return { armed, hintVisible, handlers: { onWheel, onPointerDown, onPointerLeave } };
}

/** Brief, non-blocking hint shown over the canvas on the first plain wheel. */
export function WheelZoomHint({ visible }: { visible: boolean }): ReactElement | null {
  if (!visible) return null;
  return createElement(
    "div",
    {
      role: "status",
      "data-testid": "wheel-zoom-hint",
      className: "pointer-events-none absolute inset-x-0 top-2 z-10 flex justify-center",
    },
    createElement(
      "span",
      { className: "rounded-full border border-outline bg-surface-elevated px-3 py-1 text-xs text-ink-secondary shadow-sm" },
      wheelZoomHintText(),
    ),
  );
}
