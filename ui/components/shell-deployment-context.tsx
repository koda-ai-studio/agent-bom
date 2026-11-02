"use client";

import { createContext, useContext } from "react";

import { useDeploymentContext, type DeploymentContextState } from "@/hooks/use-deployment-context";
import { isDemoDataView } from "@/lib/demo-data";
import { useCaptureMode } from "@/lib/use-capture-mode";

const ShellDeploymentContext = createContext<DeploymentContextState | null>(null);

/** One posture-counts read for the shell: nav, demo-data banner and identity chip share it. */
export function ShellDeploymentProvider({ children }: { children: React.ReactNode }) {
  const value = useDeploymentContext();
  return <ShellDeploymentContext.Provider value={value}>{children}</ShellDeploymentContext.Provider>;
}

/** The shell's shared counts; an isolated render outside the shell reads them itself. */
export function useShellDeploymentContext(): DeploymentContextState {
  const shared = useContext(ShellDeploymentContext);
  const own = useDeploymentContext({ enabled: shared === null });
  return shared ?? own;
}

export function useDemoDataView(): boolean {
  const { counts } = useShellDeploymentContext();
  const captureMode = useCaptureMode();
  return isDemoDataView({ captureMode, scanSources: counts?.scan_sources });
}
