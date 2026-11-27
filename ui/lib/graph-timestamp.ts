/** Unambiguous graph evidence time, including its timezone. */
export function graphTimestamp(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Unknown time" : `${date.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}
