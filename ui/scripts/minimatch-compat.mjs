// Tooling-only compatibility for Redocly 1.x and legacy ESLint plugins.
// Keep the patched minimatch engine while exposing its former callable CJS API.
// Loaded explicitly by lint/codegen commands; never loaded by the dashboard.
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const modern = require("minimatch");
const cached = require.cache[require.resolve("minimatch")];
if (typeof modern !== "function") {
  if (!cached || typeof modern.minimatch !== "function" || typeof modern.Minimatch !== "function") {
    throw new Error("Unsupported minimatch tooling export shape");
  }
  cached.exports = Object.assign(modern.minimatch, modern);
}
