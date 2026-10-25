import { describe, expect, it } from "vitest";

import { scanText } from "../scripts/static-demo-leak-scan.mjs";

// Real-shaped values are assembled at runtime so this file never holds one.
const join = (...parts: string[]) => parts.join("");

describe("static demo leak scanner", () => {
  it.each([
    ["AWS account id", join("arn:aws:iam::", "4829", "1736", "5501", ":role/x")],
    ["email", join("ops.lead", "@", "acme-corp.io")],
    ["public IP", join("ip ", "52.", "14.", "201.", "9")],
    ["private IP", join("host ", "10.", "4.", "2.", "77")],
    ["AWS key", join("AK", "IA", "Q3XZ7P2M", "R9KD4LWA")],
    ["GitHub token", join("gh", "p_", "a".repeat(18), "B".repeat(18))],
    ["private key", join("-----BEGIN ", "RSA PRIVATE", " KEY-----")],
    ["home path", join("/Us", "ers/", "jdoe", "/work")],
    ["linux home", join("/ho", "me/", "jdoe", "/.aws")],
    ["internal host", join("db.", "corp", ".internal")],
    ["API base", join("http://local", "host:8422", "/v1/graph")],
  ])("flags a planted %s", (_label, value) => {
    expect(scanText(`{"x":"${value}"}`, "planted.json").length).toBeGreaterThan(0);
  });

  it.each([
    ["documented example account", "arn:aws:iam::123456789012:role/demo"],
    ["example email", "analyst@example.com"],
    ["documentation IP", "198.51.100.7 and 203.0.113.9 and 192.0.2.1"],
    ["loopback", "127.0.0.1"],
    ["version numbers", "php 8.3.30 and next 16.4.1"],
    ["example host", "api.example.internal.example.com"],
  ])("allows %s", (_label, value) => {
    expect(scanText(value, "ok.json")).toEqual([]);
  });
});

describe("static demo leak scanner allowances stay narrow", () => {
  it("allows only the exact reviewed literal", () => {
    expect(scanText("http://127.0.0.1:8422", "a.js")).toEqual([]);
    expect(scanText("http://127.0.0.1:9000/v1", "a.js")).toHaveLength(1);
    expect(scanText("ops@project.iam.gserviceaccount.com", "a.js")).toHaveLength(1);
  });

  it("ignores leading-zero dotted numbers and SVG path data but not IPs in data", () => {
    expect(scanText("14.46.05.15", "a.json")).toEqual([]);
    expect(scanText("d=\"M2.8.68.74\"", "logo.svg")).toEqual([]);
    expect(scanText("2.8.68.74", "a.json")).toHaveLength(1);
  });
});

describe("static demo leak scanner digests", () => {
  it("does not read 12 digits inside a hex digest as an account id", () => {
    expect(scanText(`"sha256:20b763297d933e0a${"0556"}${"3452"}${"7136"}eabbb89f"`, "a.json")).toEqual([]);
    expect(scanText(`"account":"${"0556"}${"3452"}${"7136"}"`, "a.json")).toHaveLength(1);
  });
});
