/** Plain-language labels for internal ranking values shown to people. */

const BAND_LABELS: Record<string, string> = {
  "pulsing-red": "Critical",
  red: "High",
  amber: "Medium",
  green: "Low",
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

/** Mirrors the backend band thresholds (symbol_reach_triage.band_from_composite). */
export function exposurePriorityLabel(band: string, score: number | undefined): string {
  const level = BAND_LABELS[band.trim().toLowerCase()];
  const base = level ? `${level} exposure priority` : `Exposure priority ${band}`;
  return typeof score === "number" ? `${base} · ${score.toFixed(0)}/100` : base;
}

const TIER_LABELS: Record<number, string> = {
  3: "Reached from an agent or credential",
  2: "Finding on the path",
  1: "Exposure without a finding",
  0: "No finding or exposure",
};

/** Mirrors attack_path_queue_rank._TIER_LABELS. */
export function evidenceTierLabel(tier: number): string {
  return TIER_LABELS[tier] ?? `Evidence tier ${tier}`;
}
