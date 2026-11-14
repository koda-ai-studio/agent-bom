/** Decode one percent-encoded node-id segment for display; malformed input is shown as recorded. */
export function decodeNodeIdPart(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
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
