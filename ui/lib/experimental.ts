"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { ExperimentalFeatureHealth } from "@/lib/api-types";

export type ExperimentalState =
  | { status: "loading" }
  | { status: "unknown" }
  | { status: "enabled" | "disabled"; feature: ExperimentalFeatureHealth };

/** Live enablement of one registered experimental feature, read from /v1/system/health. */
export function useExperimentalFeature(id: string): ExperimentalState {
  const [state, setState] = useState<ExperimentalState>({ status: "loading" });
  useEffect(() => {
    let active = true;
    api.systemHealth()
      .then(health => {
        if (!active) return;
        const feature = health.experimental_features?.find(item => item.id === id);
        setState(feature ? { status: feature.enabled ? "enabled" : "disabled", feature } : { status: "unknown" });
      })
      .catch(() => { if (active) setState({ status: "unknown" }); });
    return () => { active = false; };
  }, [id]);
  return state;
}
