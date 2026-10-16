import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { createHash } from "node:crypto";
import { agentSource } from "@/lib/agent-source";
import { AgentSourceMark } from "@/components/agent-source-mark";

describe("recorded agent source identity", () => {
  it.each([
    ["claude-code", "claude", "Claude Code"], [" CLAUDE-DESKTOP ", "claude", "Claude Desktop"],
    ["cursor", "cursor", "Cursor"], ["codex-cli", "openai", "OpenAI Codex"],
    ["vscode-copilot", "copilot", "VS Code Copilot"], ["windsurf", "windsurf", "Windsurf"],
    ["cortex-code", "snowflake", "Cortex Code"], ["amazon-q", "aws", "Amazon Q"],
  ])("maps %s from its exact type", (agentType, id, label) => {
    expect(agentSource({ nodeType: "agent", agentType })).toMatchObject({ id, label });
  });

  it("prefers the recorded client over its model or hosting provider", () => {
    expect(agentSource({ agentType: "cursor", attributes: { provider: "openai", cloud_provider: "aws" } })?.id).toBe("cursor");
    expect(agentSource({ attributes: { cloud_provider: "aws", model: "claude-sonnet" } })).toBeNull();
    expect(agentSource({ attributes: { name: "Claude Code", label: "cursor" } })).toBeNull();
    expect(agentSource({ nodeType: "server", agentType: "claude-code" })).toBeNull();
  });

  it("uses explicit sources only when their identity is unambiguous", () => {
    expect(agentSource({ dataSources: ["anthropic", "claude"] })?.id).toBe("claude");
    expect(agentSource({ attributes: { vendor: "openai" } })?.id).toBe("openai");
    expect(agentSource({ dataSources: ["claude", "cursor"] })).toBeNull();
    expect(agentSource({ attributes: { vendor: "claude", provider: "cursor" } })).toBeNull();
    for (const agentType of ["custom", "constructor", "__proto__", "https://tracking.example/logo.svg", "claude-like"])
      expect(agentSource({ agentType })).toBeNull();
  });

  it("falls back to a labeled monogram when a bundled logo fails", () => {
    const source = agentSource({ agentType: "codex-cli" });
    const { container } = render(<AgentSourceMark source={source} className="h-8 w-8" />);
    const mark = screen.getByRole("img", { name: "Source: OpenAI Codex" });
    fireEvent.error(container.querySelector("img")!);
    expect(mark).toHaveTextContent("OA");
    expect(container.querySelector("img")).toBeNull();
  });

  it("has an honest mark or monogram for each supported client and a neutral custom fallback", () => {
    const models = readFileSync(resolve(__dirname, "../../src/agent_bom/models.py"), "utf8");
    const body = models.split("class AgentType(str, Enum):")[1]!.split("class TransportType")[0]!;
    const types = [...body.matchAll(/= "([^"]+)"/g)].map(match => match[1]!);
    for (const agentType of types.filter(type => type !== "custom")) {
      const source = agentSource({ agentType });
      expect(source, agentType).not.toBeNull();
      if (source?.src) expect(existsSync(resolve(__dirname, "../public", source.src.slice(1)))).toBe(true);
    }
    const { container } = render(<AgentSourceMark source={null} />);
    expect(container.querySelector(".lucide-bot")).not.toBeNull();
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
  });

  it("ships exact copies of the attributed local logo assets", () => {
    const manifest = JSON.parse(readFileSync(resolve(__dirname, "../public/logos/agent-source-provenance.json"), "utf8"));
    for (const asset of manifest.assets) {
      const data = readFileSync(resolve(__dirname, "../..", asset.path));
      expect(createHash("sha256").update(data).digest("hex")).toBe(asset.sha256);
      expect(data.equals(readFileSync(resolve(__dirname, "../..", asset.repository_source)))).toBe(true);
    }
  });
});
