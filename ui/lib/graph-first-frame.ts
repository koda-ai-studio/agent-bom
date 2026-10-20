/**
 * Whether the default canvas must wait before its first frame.
 *
 * The default view focuses the first agent once the ranked graph page and the
 * attack-path queue (which contributes agent context) have both arrived.
 * Rendering earlier shows a findings-only frame that is replaced a moment later.
 */
export function graphFirstFramePending({ awaitingAutoFocus, graphLoaded, queueSettled, agentCount }: {
  /** The page will auto-focus an agent: no URL state, lens or investigation chose the view. */
  awaitingAutoFocus: boolean;
  graphLoaded: boolean;
  queueSettled: boolean;
  agentCount: number;
}): boolean {
  if (!awaitingAutoFocus) return false;
  if (!graphLoaded || !queueSettled) return true;
  return agentCount > 0;
}
