import { expect, it } from "vitest";
import { entitySource } from "@/lib/agent-source";
it("never guesses branding from names, collector lists or conflicting metadata", () => {
  expect(entitySource({ nodeType: "role", dataSources: ["aws"] })).toBeNull();
  expect(entitySource({ nodeType: "role", attributes: { provider: "aws", vendor: "unknown" } })).toBeNull();
  expect(entitySource({ nodeType: "role", attributes: { provider: "aws", vendor: "azure" } })).toBeNull();
  expect(entitySource({ nodeType: "package", attributes: { provider: "aws" } })).toBeNull();
});
it("uses recorded identity provider metadata", () => {
  expect(entitySource({ nodeType: "role", attributes: { provider: "aws" } })?.id).toBe("aws");
});
