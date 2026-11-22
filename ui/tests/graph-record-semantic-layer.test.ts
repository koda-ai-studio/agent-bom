import { expect, it } from "vitest";
import { recordSemanticLayer } from "@/lib/graph-semantic-columns";

it("reads a node record's layer by the API rule, so unstamped records land in the same column", () => {
  expect(recordSemanticLayer({ entity_type: "agent", semantic_layer: "tool" })).toBe("tool");
  expect(recordSemanticLayer({ entity_type: "agent", attributes: { semantic_layer: "app" } })).toBe("app");
  expect(recordSemanticLayer({ entity_type: "container", dimensions: { surface: "api_gateway" } })).toBe("api_gateway");
  // A surface that is not a layer name never overrides the kind.
  expect(recordSemanticLayer({ entity_type: "container", dimensions: { surface: "container-image" } })).toBe("infra");
  expect(recordSemanticLayer({ entity_type: "agent" })).toBe("orchestration");
  expect(recordSemanticLayer({ entity_type: "server" })).toBe("mcp_server");
  expect(recordSemanticLayer({ entity_type: "ci_job", semantic_layer: "not-a-layer" })).toBe("ci");
  expect(recordSemanticLayer({ entity_type: "unknown_kind" })).toBeUndefined();
});
