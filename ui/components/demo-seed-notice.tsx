"use client";

import { usePathname } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { api } from "@/lib/api";

export const DEMO_SEED_POLL_MS = 3_000;

function reloadPage() {
  window.location.reload();
}

/**
 * Shell-wide notice while the demo estate is still seeding.
 *
 * `/health` answers before the seed lands (liveness must), so a first load can
 * read partial counts. While `/health` reports `demo_seed: "pending"` this says
 * so on every page and polls; when the seed lands it reloads once so every
 * panel re-reads the settled estate. Outside demo mode it renders nothing.
 * The overview carries its own seeding notice, so the text is not repeated there.
 */
export function DemoSeedNotice({ reload = reloadPage }: { reload?: () => void }) {
  const pathname = usePathname();
  const [pending, setPending] = useState(false);
  const sawPending = useRef(false);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const schedule = () => {
      timer = setTimeout(check, DEMO_SEED_POLL_MS);
    };
    function check() {
      api.health().then(
        (res) => {
          if (cancelled) return;
          if (res.demo_seed === "pending") {
            sawPending.current = true;
            setPending(true);
            schedule();
            return;
          }
          setPending(false);
          if (sawPending.current) reload();
        },
        () => {
          if (!cancelled && sawPending.current) schedule();
        },
      );
    }
    check();
    return () => {
      cancelled = true;
      if (timer !== undefined) clearTimeout(timer);
    };
  }, [reload]);

  if (!pending || pathname === "/") return null;
  return (
    <p
      role="status"
      aria-label="Demo estate seeding"
      className="mb-4 rounded-lg border border-outline px-3 py-2 text-sm text-ink-secondary"
    >
      Seeding the demo estate. Counts are partial until it finishes; this page reloads when it lands, usually within a minute or two.
    </p>
  );
}
