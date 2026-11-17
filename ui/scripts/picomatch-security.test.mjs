import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import test from "node:test";

const require = createRequire(import.meta.url);
const consumers = ["vite", "vitest", "tinyglobby", "@rollup/pluginutils", "@next/eslint-plugin-next"];

test("the lockfile contains only the reviewed matcher artifact", () => {
  const lock = JSON.parse(readFileSync(new URL("../package-lock.json", import.meta.url), "utf8"));
  const matchers = Object.entries(lock.packages).filter(([path]) => path.endsWith("/picomatch"));
  assert.ok(matchers.length > 0);
  for (const [, metadata] of matchers) {
    assert.equal(metadata.name, "@ryotsu/picomatch");
    assert.equal(metadata.version, "4.0.7-a");
    assert.equal(metadata.integrity, "sha512-JroBFEmaejC7szGSfqOhF1QZHLKvX2wTA1+fWyfkpy3BjzdQKNPLKa2FtgeKVUDy5/UPUNkXEeCHJ5ZRBMLTVA==");
  }
});

for (const consumer of consumers) {
  test(`${consumer} rejects adversarial repeated extglobs within a bounded process`, () => {
    const consumerRequire = createRequire(require.resolve(consumer));
    const entry = consumerRequire.resolve("picomatch");
    const child = spawnSync(process.execPath, ["-e", `
      const assert = require('node:assert/strict');
      const pm = require(process.argv[1]);
      for (const length of [40, 80, 160]) {
        for (const pattern of ['+(*a)b', '+(*a)', '+(*)(x)', '*(*a)b']) {
          assert.equal(pm(pattern)('a'.repeat(length) + '!'), false);
        }
      }
      assert.equal(pm('+(*a)')('aaa'), true);
      assert.equal(pm('+(*a)b')('aaab'), true);
      assert.equal(pm('src/**/*.{ts,tsx}')('src/app/page.tsx'), true);
      assert.equal(pm('src/**/*.{ts,tsx}')('src/app/page.js'), false);
      assert.equal(pm('**/*.ts', { dot: true })('.hidden/file.ts'), true);
      assert.equal(pm('**/*.ts', { ignore: '**/vendor/**' })('src/vendor/a.ts'), false);
      assert.equal(pm('+(foo|bar).js')('foobar.js'), true);
      assert.equal(pm('file[0-9].js')('file4.js'), true);
    `, entry], { encoding: "utf8", timeout: 3000 });
    assert.ifError(child.error);
    assert.equal(child.status, 0, child.stderr);
  });
}
