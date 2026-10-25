#!/usr/bin/env node
/**
 * Fail the public static demo if its bundle carries anything that looks real:
 * account ids, emails, routable IPs, key material, home paths, internal hosts
 * or an API base URL the browser could call.
 */
import fs from "node:fs/promises";
import path from "node:path";

const EXAMPLE_ACCOUNT_IDS = new Set(["123456789012", "111122223333", "444455556666", "777788889999", "000000000000"]);
const EXAMPLE_EMAIL_DOMAIN = /(^|\.)(example\.(com|org|net)|example|test|invalid|localhost)$/i;
const DOC_IP = [/^192\.0\.2\./, /^198\.51\.100\./, /^203\.0\.113\./, /^127\./, /^0\.0\.0\.0$/, /^255\.255\.255\.255$/, /^169\.254\.169\.254$/];

// Reviewed UI copy, matched exactly: each is text a user reads, never a value
// the demo fetches or a record from an estate. The request check proves no call.
const REVIEWED_LITERALS = new Map([
  ["api-base-url:http://127.0.0.1:8422", "copyable self-host CLI command in the persona start routes"],
  ["email:agent-bom@project.iam.gserviceaccount.com", "GCP service-account placeholder in the connection form"],
]);

const OCTET = "(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";

const RULES = [
  {
    rule: "aws-account-id",
    pattern: /(?<![\w.])(\d{12})(?![\w.])/g,
    allow: (m) => EXAMPLE_ACCOUNT_IDS.has(m[1]),
  },
  {
    rule: "email",
    pattern: /\b[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})\b/g,
    allow: (m) => EXAMPLE_EMAIL_DOMAIN.test(m[1]),
  },
  {
    rule: "ip-address",
    pattern: new RegExp(`(?<![\\d.])(${OCTET}(?:\\.${OCTET}){3})(?![\\d.])`, "g"),
    allow: (m) => DOC_IP.some((re) => re.test(m[1])),
    // Vector path data is numeric soup ("2.8.68.74"); other rules still scan SVGs.
    skipExtensions: [".svg"],
  },
  { rule: "aws-access-key", pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { rule: "github-token", pattern: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { rule: "slack-token", pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}/g },
  { rule: "openai-style-key", pattern: /\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b/g },
  { rule: "google-api-key", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { rule: "private-key", pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g },
  {
    rule: "home-path",
    pattern: /(?:\/Users\/|\/home\/|[A-Z]:\\\\?Users\\\\?)([A-Za-z0-9._-]+)/g,
    allow: (m) => /^(user|username|you|me|runner|example|demo|\.\.\.)$/i.test(m[1]),
  },
  {
    rule: "internal-hostname",
    pattern: /\b(?:[a-z0-9-]+\.)+(?:internal|corp|intranet|lan)\b/gi,
    allow: (m) => /example/i.test(m[0]),
  },
  {
    rule: "api-base-url",
    pattern: /\b(?:https?|wss?):\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(?::\d+)?/gi,
  },
];

/** Every real-looking value in one file's text. */
export function scanText(text, file) {
  const findings = [];
  for (const { rule, pattern, allow, skipExtensions } of RULES) {
    if (skipExtensions?.some((ext) => file.endsWith(ext))) continue;
    pattern.lastIndex = 0;
    for (const match of text.matchAll(pattern)) {
      if (allow?.(match) || REVIEWED_LITERALS.has(`${rule}:${match[0]}`)) continue;
      findings.push({ file, rule, match: match[0].slice(0, 80) });
    }
  }
  return findings;
}

const SCANNED = new Set([".html", ".json", ".js", ".txt", ".css", ".map", ".svg", ".webmanifest"]);

export async function scanDirectory(root) {
  const findings = [];
  const walk = async (dir) => {
    for (const entry of await fs.readdir(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) await walk(full);
      else if (SCANNED.has(path.extname(entry.name))) {
        findings.push(...scanText(await fs.readFile(full, "utf8"), path.relative(root, full)));
      }
    }
  };
  await walk(root);
  return findings;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const root = process.argv[2];
  if (!root) {
    console.error("usage: static-demo-leak-scan.mjs <export-dir>");
    process.exit(2);
  }
  const findings = await scanDirectory(path.resolve(root));
  for (const f of findings) console.error(`${f.rule}\t${f.file}\t${f.match}`);
  console.log(`static demo leak scan: ${findings.length} finding(s) in ${root}`);
  process.exit(findings.length ? 1 : 0);
}
