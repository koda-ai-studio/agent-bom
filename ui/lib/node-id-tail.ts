/** Decode one percent-encoded node-id segment for display; malformed input is shown as recorded. */
export function decodeNodeIdPart(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/**
 * A whole node id with each segment decoded for accessible names and tooltips
 * (``agent:Team%205`` -> ``agent:Team 5``). Display only: the raw id stays the key.
 */
export function readableNodeId(id: string): string {
  return id.split(/([:/])/).map((part, index) => (index % 2 === 1 ? part : decodeNodeIdPart(part))).join("");
}

/**
 * Readable last segment of a graph node id (``kubernetes:workload:ns/app`` -> ``app``,
 * ``agent:Cursor%20Workspace`` -> ``Cursor Workspace``). Splits before decoding so an
 * encoded ``:`` or ``/`` stays part of the name. Display only: the raw id stays the key.
 */
export function nodeIdTail(id: string): string {
  const tail = id.split(/[:/]/).filter(Boolean).at(-1);
  return tail ? decodeNodeIdPart(tail) : id;
}
