import { afterEach, describe, expect, it, vi } from "vitest";
import { getDisplayApiUrl } from "@/lib/runtime-config";

afterEach(() => vi.unstubAllGlobals());

describe("deployment API display", () => {
  it.each(["https://security.example", "http://localhost:8422", "http://127.0.0.1:3000"])("shows the actual origin for %s", (origin) => {
    vi.stubGlobal("window", { location: { origin }, __AGENT_BOM_CONFIG__: { apiUrl: "" } });
    expect(getDisplayApiUrl()).toBe(origin);
  });

  it("resolves a same-origin reverse-proxy prefix", () => {
    vi.stubGlobal("window", { location: { origin: "https://security.example" }, __AGENT_BOM_CONFIG__: { apiUrl: "/control-plane" } });
    expect(getDisplayApiUrl()).toBe("https://security.example/control-plane");
  });

  it("does not display a rejected cross-origin override as the active endpoint", () => {
    vi.stubGlobal("window", { location: { origin: "https://security.example" }, __AGENT_BOM_CONFIG__: { apiUrl: "https://untrusted.example" } });
    expect(getDisplayApiUrl()).toBe("https://security.example");
  });
});
