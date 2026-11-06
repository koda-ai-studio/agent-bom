"use client";

import { useEffect, useState } from "react";

import { AIStatusNotice, type AIStatus } from "@/components/ai-advice";
import { getAIStatus } from "@/lib/api-ai-advice";

/** Reads the tenant's AI state once. If it cannot load, the page says nothing rather than guessing. */
export function AIAdviceStatusLine() {
  const [status, setStatus] = useState<AIStatus | null>(null);
  useEffect(() => {
    let active = true;
    getAIStatus().then(
      (body) => {
        if (active) setStatus(body as AIStatus);
      },
      () => undefined,
    );
    return () => {
      active = false;
    };
  }, []);
  return <AIStatusNotice status={status} />;
}
