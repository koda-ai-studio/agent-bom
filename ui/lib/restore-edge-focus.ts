// How long a closed inspector keeps watching for React Flow to redraw the
// edge it returns focus to. A keyed canvas remount or a re-fit after the dock
// closes can land several frames after close on a slow machine.
const RESTORE_WINDOW_MS = 1_500;

type Focusable = HTMLElement | SVGElement;
const focusable = (element: Element | null | undefined): element is Focusable =>
  element instanceof HTMLElement || element instanceof SVGElement;
const focusLost = () => !document.activeElement || document.activeElement === document.body;

/** The nearest ancestor of the inspector that also holds a graph canvas. */
function graphViewOf(inspector: Element | null): Element | null {
  let scope = inspector?.parentElement ?? null;
  while (scope && !scope.querySelector(".react-flow")) scope = scope.parentElement;
  return scope;
}

/**
 * Capture where focus returns when a relationship inspector closes.
 *
 * The invoker is whatever held focus when the inspector opened. When the
 * inspector remounts while open, focus is already on the body or inside the
 * inspector, so it falls back to the inspected edge in its own graph view.
 * Edges are resolved by id inside the canvas host, which survives a React
 * Flow remount, so focus never lands on another investigation's edge.
 */
export function captureFocusReturn(previous: Element | null, inspector: Element | null, inspectedEdgeId: string): () => void {
  const invoker = previous && previous !== document.body && !inspector?.contains(previous) ? previous : null;
  const invokerCanvas = invoker?.closest(".react-flow");
  const host = invokerCanvas?.parentElement ?? (invoker ? null : graphViewOf(inspector));
  const edgeId = invoker ? invoker.closest(".react-flow__edge")?.getAttribute("data-id") ?? null : inspectedEdgeId;
  const target = (): Focusable | null => {
    if (invoker?.isConnected && focusable(invoker)) return invoker;
    if (!host || !edgeId) return null;
    const match = Array.from(host.querySelectorAll(".react-flow__edge")).find(element => element.getAttribute("data-id") === edgeId);
    return focusable(match) ? match : null;
  };
  const restore = () => target()?.focus({ preventScroll: true });

  return () => {
    restore();
    if (!host || !edgeId) {
      requestAnimationFrame(() => { if (focusLost()) restore(); });
      return;
    }
    const observer = new MutationObserver(() => { if (focusLost()) restore(); });
    let timer = 0;
    const onFocusIn = (event: FocusEvent) => {
      const landed = event.target instanceof Element ? event.target.closest(".react-flow__edge") : null;
      if (landed?.getAttribute("data-id") !== edgeId) stop();
    };
    function stop() {
      observer.disconnect();
      window.clearTimeout(timer);
      document.removeEventListener("focusin", onFocusIn, true);
    }
    observer.observe(host, { childList: true, subtree: true });
    document.addEventListener("focusin", onFocusIn, true);
    timer = window.setTimeout(stop, RESTORE_WINDOW_MS);
    requestAnimationFrame(() => { if (focusLost()) restore(); });
  };
}
