import type {
  GovernanceReport,
  SelfPostureReport,
  SkillsScanReport,
  SkillsScanRequest,
  BlueprintListResponse,
  BlueprintDetailResponse,
  BlueprintVersionResponse,
  BlueprintSeedResponse,
} from "./api-types";
import { get, post } from "./api-transport";

export const governanceApi = {

  // Operator self-posture — this instance's own control-plane hardening
  getSelfPosture: () => get<SelfPostureReport>("/v1/self-posture"),


  // ── Skills scan (#4790): same shared scanner the CLI/MCP use, over REST ──
  /** This tenant's latest persisted skills scan (honest empty when none). */
  getSkillsScan: () => get<SkillsScanReport>("/v1/skills/scan", { ttlMs: 0 }),

  /** Trigger a skills scan over confined scan-root targets; returns verdicts inline. */
  runSkillsScan: (body: SkillsScanRequest) => post<SkillsScanReport>("/v1/skills/scan", body),


  // Governance
  getGovernance: (days = 30) => get<GovernanceReport>(`/v1/governance?days=${days}`),


  // Governance blueprints (persisted AI-system blueprints + versioning + approval)
  listBlueprints: (limit = 50, offset = 0) =>
    get<BlueprintListResponse>(`/v1/governance/blueprints?limit=${limit}&offset=${offset}`),

  getBlueprint: (blueprintId: string) =>
    get<BlueprintDetailResponse>(`/v1/governance/blueprints/${encodeURIComponent(blueprintId)}`),

  seedBlueprints: () => post<BlueprintSeedResponse>("/v1/governance/blueprints/seed", {}),

  submitBlueprintVersion: (blueprintId: string, version: number) =>
    post<BlueprintVersionResponse>(
      `/v1/governance/blueprints/${encodeURIComponent(blueprintId)}/versions/${version}/submit`,
      {}
    ),

  approveBlueprintVersion: (blueprintId: string, version: number, note = "") =>
    post<BlueprintVersionResponse>(
      `/v1/governance/blueprints/${encodeURIComponent(blueprintId)}/versions/${version}/approve`,
      { note }
    ),

  rejectBlueprintVersion: (blueprintId: string, version: number, note = "") =>
    post<BlueprintVersionResponse>(
      `/v1/governance/blueprints/${encodeURIComponent(blueprintId)}/versions/${version}/reject`,
      { note }
    ),
};
