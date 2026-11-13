import { describe, expect, it } from "vitest";
import { canvasCaption } from "@/lib/graph-canvas-caption";

describe("canvasCaption", () => {
  it("names a path finding by its rule, since the canvas already draws the path", () => {
    const title = "AI agent can reach a credential or privileged tool: Claude Review Bot → research-filesystem → ANTHROPIC_API_KEY";
    expect(canvasCaption(title, "misconfiguration")).toEqual({ text: "AI agent can reach a credential or privileged tool", shortened: true });
  });

  it("never cuts a long finding title inside a word", () => {
    const title = "Container runs as root with a writable root filesystem and an unrestricted service account token mounted";
    const { text, shortened } = canvasCaption(title, "misconfiguration");
    expect(shortened).toBe(true);
    expect(text.endsWith("…")).toBe(true);
    expect(title.startsWith(text.slice(0, -1))).toBe(true);
    expect(title[text.length - 1]).toBe(" ");
    expect(text.length).toBeLessThanOrEqual(61);
  });

  it("keeps names of assets and short titles whole", () => {
    expect(canvasCaption("research-filesystem", "server")).toEqual({ text: "research-filesystem", shortened: false });
    expect(canvasCaption("CVE-2023-30861", "vulnerability")).toEqual({ text: "CVE-2023-30861", shortened: false });
    const assetTitle = "an asset label: with a colon → that is not a finding title";
    expect(canvasCaption(assetTitle, "server").text).toBe(assetTitle);
  });
});
