/** Wrapped positions retained for the overview graph and its product captures. */
export function serpentinePositions(
  orderedIds: readonly string[],
  columns: number,
  step: { column: number; row: number },
): Map<string, { x: number; y: number; reverse: boolean }> {
  const perRow = Math.max(1, Math.floor(columns));
  return new Map(orderedIds.map((id, index) => {
    const row = Math.floor(index / perRow);
    const column = index % perRow;
    const reverse = row % 2 === 1;
    return [id, { x: (reverse ? perRow - 1 - column : column) * step.column, y: row * step.row, reverse }];
  }));
}
