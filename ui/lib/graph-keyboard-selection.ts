import type { KeyboardEvent } from "react";

/** React Flow focuses nodes with Enter but does not invoke the click inspector. */
export function activateGraphNodeFromKeyboard(event: KeyboardEvent): boolean {
  if (!["Enter", " "].includes(event.key) || !(event.target instanceof HTMLElement) || !event.target.matches(".react-flow__node")) return false;
  event.preventDefault();
  event.stopPropagation();
  event.target.click();
  return true;
}
