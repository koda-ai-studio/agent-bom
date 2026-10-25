/** Shared fixture data for the product-proof captures and the read-only demo. */
import fs from "node:fs/promises";
import { readFileSync } from "node:fs";
import path from "node:path";
import { gunzipSync } from "node:zlib";

const UI_ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");

export const CREATED_AT = "2026-06-03T20:30:00Z";

// Scan-relative times in the recorded overview proof. Feed dates such as
// kev_due_date are published facts and are never moved.
const SCAN_RELATIVE_KEYS = new Set([
  "latest_scan_at", "latest_scan", "scan_timestamp", "generated_at", "created_at", "completed_at",
  "discovered_at", "first_seen", "last_seen", "first_recorded_at", "last_recorded_at", "sla_due_at",
]);
const SAME_SCAN_MS = 60_000;

/**
 * Re-date the proof so its scan is the fixture snapshot: every scan-relative
 * time moves by the same offset (ages and SLA windows keep their length), and
 * times recorded during the scan itself become exactly CREATED_AT.
 */
export function alignProofToSnapshot(proof, snapshotAt = CREATED_AT) {
  const scanAt = Date.parse(proof.responses["/v1/overview"].headline.latest_scan_at);
  const target = Date.parse(snapshotAt);
  const offset = target - scanAt;
  const move = (value) => {
    const at = Date.parse(value);
    if (Number.isNaN(at)) return value;
    return Math.abs(at - scanAt) <= SAME_SCAN_MS ? snapshotAt : new Date(at + offset).toISOString();
  };
  const walk = (value) => {
    if (Array.isArray(value)) return value.map(walk);
    if (!value || typeof value !== "object") return value;
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [
      key,
      SCAN_RELATIVE_KEYS.has(key) && typeof item === "string" ? move(item) : walk(item),
    ]));
  };
  return { ...proof, captured_at: snapshotAt, responses: walk(proof.responses) };
}

/** The overview proof as served: one snapshot, dated at the fixture time. */
export async function loadOverviewProof() {
  const proof = JSON.parse(gunzipSync(await fs.readFile(path.join(UI_ROOT, "fixtures/overview-proof.json.gz"))).toString());
  return alignProofToSnapshot(proof);
}

const INTEL_CATALOG = JSON.parse(readFileSync(path.join(UI_ROOT, "fixtures/intel-sources.json"), "utf8"));
const GALLERY_ADVISORIES = JSON.parse(readFileSync(path.join(UI_ROOT, "fixtures/gallery-advisories.json"), "utf8")).advisories;
// The bundled sample is matched with these feeds; the rest of the catalog is disabled.
const SAMPLE_FEEDS = new Set(INTEL_CATALOG.sample_feeds);

/** `GET /v1/intel/sources` for the sample estate, in the product's catalog order and shape. */
export function intelSourcesFixture(syncedAt = CREATED_AT) {
  const sources = INTEL_CATALOG.sources.map(({ sync_meta_source, ...source }) => {
    const synced = SAMPLE_FEEDS.has(source.source_id);
    return {
      ...source,
      enabled: synced,
      feed_run: {
        sync_meta_source,
        status: synced ? "synced" : "freshness_unknown",
        partial_reason: null,
        last_synced: synced ? syncedAt : null,
        fetched_at: synced ? syncedAt : null,
        record_count: synced ? GALLERY_ADVISORIES.length : 0,
        last_validated_at: null,
        content_hash: null,
        etag: null,
        last_modified: null,
        parse_errors: 0,
        validation_failures: 0,
        cap_hit: false,
        validation_status: source.validation_status,
      },
    };
  });
  return { schema_version: "intel.sources.v1", sources, count: sources.length };
}
