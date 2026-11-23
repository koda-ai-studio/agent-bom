#!/usr/bin/env node
// Duration-balanced Playwright shards.
//
// `playwright test --shard` splits the suite by test count in file order, so the
// slow graph specs land together and one shard runs three times as long as
// another. This plans shards from recorded per-test durations instead: every
// test location (`file:line`) is a unit, units are packed longest first into the
// least-loaded shard, and a test with no recorded duration counts as the median.
// Every test the suite lists is assigned to exactly one shard.
//
//   node scripts/e2e-shard-plan.mjs --shard 3/8      # locations for shard 3, one per line
//   node scripts/e2e-shard-plan.mjs --check 8        # every listed test is in exactly one shard
//   node scripts/e2e-shard-plan.mjs --record report.json   # rewrite e2e/shard-timings.json from a JSON report
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const UI = join(dirname(fileURLToPath(import.meta.url)), "..");
const TIMINGS = join(UI, "e2e", "shard-timings.json");

/** Walk a Playwright JSON report (from --list or a run) into `[location, seconds]` per test result. */
export function reportTests(report) {
  const out = [];
  const walk = (suite, file) => {
    const current = suite.file ?? file;
    for (const spec of suite.specs ?? []) {
      const location = `e2e/${spec.file ?? current}:${spec.line}`;
      for (const test of spec.tests ?? []) {
        const results = test.results ?? [];
        if (!results.length) out.push([location, null]);
        for (const result of results) out.push([location, result.duration / 1000]);
      }
    }
    for (const child of suite.suites ?? []) walk(child, current);
  };
  for (const suite of report.suites ?? []) walk(suite);
  return out;
}

/** Group listed tests into units keyed by location, weighted by recorded seconds (median when unknown). */
export function units(listed, timings) {
  const known = Object.values(timings).filter(Number.isFinite).sort((a, b) => a - b);
  const median = known.length ? known[Math.floor(known.length / 2)] : 1;
  const weights = new Map();
  for (const [location] of listed) weights.set(location, timings[location] ?? median);
  return [...weights].map(([location, seconds]) => ({ location, seconds }));
}

/** Longest-processing-time packing; deterministic for equal weights. */
export function plan(unitList, shards) {
  const bins = Array.from({ length: shards }, () => ({ seconds: 0, locations: [] }));
  const ordered = [...unitList].sort((a, b) => b.seconds - a.seconds || a.location.localeCompare(b.location));
  for (const unit of ordered) {
    const bin = bins.reduce((best, candidate) => (candidate.seconds < best.seconds ? candidate : best));
    bin.seconds += unit.seconds;
    bin.locations.push(unit.location);
  }
  for (const bin of bins) bin.locations.sort();
  return bins;
}

function listTests() {
  const output = execFileSync("npx", ["playwright", "test", "--list", "--reporter=json"], {
    cwd: UI,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    stdio: ["ignore", "pipe", "inherit"],
  });
  return reportTests(JSON.parse(output.slice(output.indexOf("{"))));
}

function readTimings() {
  return JSON.parse(readFileSync(TIMINGS, "utf8"));
}

function main(argv) {
  const [flag, value] = argv;
  if (flag === "--record") {
    const totals = {};
    for (const [location, seconds] of reportTests(JSON.parse(readFileSync(value, "utf8")))) {
      if (seconds !== null) totals[location] = Math.round(((totals[location] ?? 0) + seconds) * 10) / 10;
    }
    const sorted = Object.fromEntries(Object.entries(totals).sort(([a], [b]) => a.localeCompare(b)));
    writeFileSync(TIMINGS, `${JSON.stringify(sorted, null, 1)}\n`);
    console.error(`recorded ${Object.keys(sorted).length} test locations to ${relative(process.cwd(), TIMINGS)}`);
    return 0;
  }
  if (flag === "--check") {
    const shards = Number(value);
    const listed = listTests();
    const bins = plan(units(listed, readTimings()), shards);
    const assigned = bins.flatMap(bin => bin.locations);
    const expected = new Set(listed.map(([location]) => location));
    if (assigned.length !== expected.size || new Set(assigned).size !== expected.size || assigned.some(l => !expected.has(l))) {
      console.error("shard plan does not assign every listed test location exactly once");
      return 1;
    }
    if (bins.some(bin => !bin.locations.length)) {
      console.error("a shard would be empty; Playwright runs the whole suite when given no locations");
      return 1;
    }
    for (const [i, bin] of bins.entries()) console.error(`shard ${i + 1}/${shards}: ${bin.locations.length} locations, ~${Math.round(bin.seconds)}s`);
    return 0;
  }
  if (flag === "--shard") {
    const match = /^(\d+)\/(\d+)$/.exec(value ?? "");
    if (!match || Number(match[1]) < 1 || Number(match[1]) > Number(match[2])) {
      console.error("usage: --shard <current>/<total>");
      return 2;
    }
    const bins = plan(units(listTests(), readTimings()), Number(match[2]));
    const mine = bins[Number(match[1]) - 1];
    if (!mine.locations.length) {
      console.error("this shard has no tests; refusing to print an empty list, which would run the whole suite");
      return 1;
    }
    console.error(`shard ${value}: ${mine.locations.length} locations, ~${Math.round(mine.seconds)}s recorded`);
    process.stdout.write(`${mine.locations.join("\n")}\n`);
    return 0;
  }
  console.error("usage: e2e-shard-plan.mjs --shard i/n | --check n | --record report.json");
  return 2;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) process.exit(main(process.argv.slice(2)));
