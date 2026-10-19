// Derive the committed product-proof screenshot set from the published docs.
// A capture is committed only when README.md, docs/ or site-docs/ embeds or
// links it. Mirrored in scripts/product_proof_curation.py, which the release
// consistency gate uses; keep both in sync.
import fs from "node:fs/promises";
import path from "node:path";

const IMAGE_DIR = "docs/images";
const MARKDOWN_ROOTS = ["README.md", "docs", "site-docs"];
export const NON_CAPTURE_IMAGES = new Set(["demo-latest.gif", "social-preview.png"]);

const MARKDOWN_TARGET = /\]\(\s*<?([^)\s>]+)/g;
const HTML_TARGET = /\b(?:src|srcset|href)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;

async function markdownFiles(root) {
  const files = [];
  for (const entry of MARKDOWN_ROOTS) {
    const full = path.join(root, entry);
    const stat = await fs.stat(full).catch(() => null);
    if (stat?.isFile()) files.push(entry);
    if (stat?.isDirectory()) {
      const nested = await fs.readdir(full, { recursive: true, withFileTypes: true });
      files.push(...nested
        .filter((item) => item.isFile() && item.name.endsWith(".md"))
        .map((item) => path.posix.join(path.relative(root, item.parentPath).split(path.sep).join("/"), item.name)));
    }
  }
  return files.sort();
}

function targets(text) {
  const found = [...text.matchAll(MARKDOWN_TARGET)].map((match) => match[1]);
  for (const match of text.matchAll(HTML_TARGET)) {
    const value = match[1] ?? match[2];
    found.push(...value.split(",").filter((part) => part.trim()).map((part) => part.trim().split(/\s+/)[0]));
  }
  return found;
}

function imageName(document, target) {
  const clean = target.split(/[?#]/, 1)[0];
  if (clean.includes("://")) {
    const marker = `/${IMAGE_DIR}/`;
    return clean.includes(marker) ? clean.split(marker).slice(1).join(marker) : null;
  }
  const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(document), clean));
  return resolved.startsWith(`${IMAGE_DIR}/`) ? resolved.slice(IMAGE_DIR.length + 1) : null;
}

export async function imageReferences(root) {
  const references = new Map();
  for (const document of await markdownFiles(root)) {
    const text = await fs.readFile(path.join(root, document), "utf8");
    for (const target of targets(text)) {
      const name = imageName(document, target);
      if (!name) continue;
      if (!references.has(name)) references.set(name, new Set());
      references.get(name).add(document);
    }
  }
  return references;
}

function isCaptureName(name) {
  return !name.includes("/") && name.endsWith(".png") && !NON_CAPTURE_IMAGES.has(name);
}

export async function curatedCaptureNames(root) {
  return [...(await imageReferences(root)).keys()].filter(isCaptureName).sort();
}
