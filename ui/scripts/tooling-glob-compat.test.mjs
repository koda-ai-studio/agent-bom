import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { Linter } from "eslint";
import jsxA11y from "eslint-plugin-jsx-a11y";
import { glob } from "glob";
import { readFileFromUrl } from "@redocly/openapi-core/lib/utils.js";

test("schema resolver applies headers only to matching URLs", async () => {
  const requests = [];
  const config = {
    headers: [{ matches: "https://schema.invalid/**", name: "X-Fixture", value: "fixture" }],
    customFetch: async (url, options) => {
      requests.push({ url, headers: options.headers });
      return new Response("openapi: 3.1.0", { headers: { "content-type": "text/yaml" } });
    },
  };
  await readFileFromUrl("https://schema.invalid/api.yaml", config);
  await readFileFromUrl("https://other.invalid/api.yaml", config);
  assert.deepEqual(requests.map(request => request.headers), [{ "X-Fixture": "fixture" }, {}]);
});

test("accessibility rules still recognize custom control patterns", () => {
  const messages = new Linter().verify("const view = <button><CustomControl /></button>;", [{
    languageOptions: { parserOptions: { ecmaFeatures: { jsx: true } } },
    plugins: { "jsx-a11y": jsxA11y },
    rules: { "jsx-a11y/control-has-associated-label": ["error", { controlComponents: ["Custom*"] }] },
  }]);
  assert.equal(messages.length, 1);
  assert.equal(messages[0].ruleId, "jsx-a11y/control-has-associated-label");
});

test("glob traverses nested sources and rejects an aborted walk", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agent-bom-glob-"));
  try {
    await mkdir(path.join(root, "nested"));
    await writeFile(path.join(root, "nested", "component.tsx"), "fixture");
    await writeFile(path.join(root, "readme.md"), "fixture");
    assert.deepEqual(await glob("**/*.{ts,tsx}", { cwd: root }), ["nested/component.tsx"]);
    await assert.rejects(glob("**/*", { cwd: root, signal: AbortSignal.abort() }));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
