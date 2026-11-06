import type { components } from "./api-schema.generated";
import { get, post } from "./api-transport";

type Schemas = components["schemas"];
export type GraphExplanation = Schemas["GraphExplanationResponse"];
export type AIStatusResponse = Schemas["AIStatusResponse"];

export function getAIStatus(): Promise<AIStatusResponse> {
  return get<AIStatusResponse>("/v1/ai/status");
}

/** On demand only: this spends the tenant's explain budget and calls a model. */
export function explainGraphSelection(input: { nodeIds: string[]; ordered: boolean; scanId?: string | undefined }): Promise<GraphExplanation> {
  return post<GraphExplanation>("/v1/graph/explain", {
    node_ids: input.nodeIds,
    ordered: input.ordered,
    ...(input.scanId ? { scan_id: input.scanId } : {}),
  });
}
