import type { ApiSchemas } from "@/lib/api-contracts/shared";

/** `GET /v1/graph/agent-architecture`, from the generated OpenAPI schema. */
export type AgentArchitectureResponse = ApiSchemas["GraphAgentArchitectureResponse"];
export type AgentHarness = ApiSchemas["AgentHarness"];
export type HarnessAgent = ApiSchemas["HarnessAgent"];
export type HarnessFlowEdge = ApiSchemas["HarnessFlowEdge"];
export type HarnessUnresolvedRoute = ApiSchemas["HarnessUnresolvedRoute"];
export type HarnessCoverage = ApiSchemas["HarnessCoverage"];
export type HarnessSummary = ApiSchemas["HarnessSummary"];
export type HarnessFlowKind = HarnessFlowEdge["kind"];
export type HarnessRole = HarnessAgent["role"];
