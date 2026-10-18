/** Copy attributed source marks without altering their vector bytes. */
import { readFile, writeFile, copyFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const sources = JSON.parse(await readFile(path.join(root, "docs/images/vendor/provenance.json"), "utf8"));
const destination = path.join(root, "ui/public/logos/agent-source-provenance.json");
const manifest = JSON.parse(await readFile(destination, "utf8"));
for (const id of ["okta", "databricks", "kubernetes", "clickhouse"]) {
  const sourcePath = `docs/images/vendor/simple-icons/${id}.svg`;
  const source = sources.assets.find(asset => asset.path === sourcePath);
  if (!source) throw new Error(`Missing attribution for ${id}`);
  const bytes = await readFile(path.join(root, sourcePath));
  if (createHash("sha256").update(bytes).digest("hex") !== source.sha256) throw new Error(`Source hash mismatch: ${id}`);
  const target = `ui/public/logos/${id}.svg`;
  await copyFile(path.join(root, sourcePath), path.join(root, target));
  manifest.assets = manifest.assets.filter(asset => asset.path !== target);
  manifest.assets.push({ ...source, path: target, repository_source: sourcePath });
}
await writeFile(destination, `${JSON.stringify(manifest, null, 2)}\n`);
