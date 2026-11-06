"use client";

import dynamic from "next/dynamic";
import { roleCanConnect } from "@/lib/roles";
import type { GraphPageModel } from "@/components/graph-page-view";

const GraphScenarioAuthoring = dynamic(() => import("@/components/graph-scenario-comparison").then(mod => mod.GraphScenarioAuthoring), { ssr: false });
const GraphScenarioComparisonPanel = dynamic(() => import("@/components/graph-scenario-comparison").then(mod => mod.GraphScenarioComparisonPanel), { ssr: false });

export function GraphScenarioPanel({ page }: { page: GraphPageModel }) {
  const {
    selectedScenario, scenarioComparison, scenarioState, loadingScenarioComparison, scenarioError, attackPathLens, snapshots,
    setScenarioState, setSelectedScanId, selectedScanId, session, setScenarios, setSelectedScenarioId, setScenarioRefreshKey,
  } = page;
  return (
    <GraphScenarioComparisonPanel
            scenario={selectedScenario}
            comparison={scenarioComparison}
            state={scenarioState}
            loading={loadingScenarioComparison}
            error={scenarioError}
            attackPathLens={attackPathLens}
            baseSnapshotAvailable={Boolean(
              selectedScenario &&
                snapshots.some(
                  (snapshot) => snapshot.scan_id === selectedScenario.base_scan_id,
                ),
            )}
            onStateChange={setScenarioState}
            onSwitchBase={() => {
              if (selectedScenario) {
                setSelectedScanId(selectedScenario.base_scan_id);
              }
            }}
            authoring={
              <GraphScenarioAuthoring
                scanId={selectedScanId}
                scenario={selectedScenario}
                session={session}
                canWrite={
                  roleCanConnect(
                    session?.role_summary?.role ?? session?.role,
                  ) &&
                  !session?.managed_trial_mode &&
                  session?.auth_method !== "managed_trial_oidc"
                }
                onSaved={(savedScenario) => {
                  setScenarios((current) => [
                    savedScenario,
                    ...current.filter(
                      (item) => item.scenario_id !== savedScenario.scenario_id,
                    ),
                  ]);
                  setSelectedScenarioId(savedScenario.scenario_id);
                  setScenarioState("proposed");
                  setScenarioRefreshKey((current) => current + 1);
                }}
              />
            }
          />
  );
}
