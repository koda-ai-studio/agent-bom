import { Hourglass, Lock, Shield, ShieldOff } from "lucide-react";
import type { RuntimeEvidenceTier } from "../lineage-nodes";

/**
 * Evidence redaction tier badge (issue #2261).
 *
 * Renders one of three states next to each evidence row so auditors can
 * see at a glance whether the underlying data is safe to keep, on a
 * short-TTL replay rotation, or dropped before it ever hits storage.
 */
export function EvidenceTierBadge({
  tier,
  captureReplay,
  notAfter,
}: {
  tier?: "safe_to_store" | "replay_only" | undefined;
  captureReplay?: boolean | undefined;
  notAfter?: string | undefined;
}) {
  if (!tier) return null;

  if (tier === "safe_to_store") {
    return (
      <div className="flex items-center gap-1.5 rounded border border-emerald-800 bg-emerald-950 px-2 py-1 text-[10px] font-mono text-emerald-300">
        <Lock className="w-3 h-3" />
        <span>Safe to store</span>
      </div>
    );
  }

  // replay_only
  if (!captureReplay) {
    return (
      <div className="flex items-center gap-1.5 rounded border border-outline bg-surface px-2 py-1 text-[10px] font-mono text-ink-secondary">
        <ShieldOff className="w-3 h-3" />
        <span>Not persisted</span>
      </div>
    );
  }

  let rotatesIn: number | null = null;
  if (notAfter) {
    const expiry = new Date(notAfter).getTime();
    if (!Number.isNaN(expiry)) {
      const deltaDays = Math.max(
        0,
        Math.floor((expiry - Date.now()) / 86_400_000),
      );
      rotatesIn = deltaDays;
    }
  }
  return (
    <div className="flex items-center gap-1.5 rounded border border-[color:var(--severity-medium-border)] bg-[color:var(--severity-medium-bg)] px-2 py-1 text-[10px] font-mono text-[color:var(--severity-medium)]">
      <Hourglass className="w-3 h-3" />
      <span>
        {rotatesIn != null ? `Rotates in ${rotatesIn} days` : "Replay only"}
      </span>
    </div>
  );
}

export function RuntimeEvidenceBadge({
  tier,
}: {
  tier?: RuntimeEvidenceTier | undefined;
}) {
  if (!tier) return null;

  const labels: Record<
    RuntimeEvidenceTier,
    { text: string; className: string }
  > = {
    static_scan: {
      text: "Static scan evidence",
      className: "border-outline bg-surface text-ink-secondary",
    },
    runtime_observed: {
      text: "Runtime observed path",
      className: "border-sky-800 bg-sky-950 text-sky-300",
    },
    runtime_blocked: {
      text: "Runtime blocked path",
      className: "border-rose-800 bg-rose-950 text-rose-300",
    },
  };
  const chip = labels[tier];
  return (
    <div
      className={`flex items-center gap-1.5 rounded border px-2 py-1 text-[10px] font-mono ${chip.className}`}
    >
      <Shield className="w-3 h-3" />
      <span>{chip.text}</span>
    </div>
  );
}
