/** Minimal static host with GitHub Pages semantics (`/x` → `x.html`) for the read-only demo export. */
import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";

const TYPES = {
  ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".json": "application/json",
  ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon", ".woff2": "font/woff2", ".txt": "text/plain",
  ".webmanifest": "application/manifest+json",
};

async function resolveFile(root, relative) {
  const safe = path.normalize(decodeURIComponent(relative)).replace(/^(\.\.(\/|\\|$))+/, "");
  const base = path.join(root, safe);
  if (base !== root && !base.startsWith(root + path.sep)) return null;
  for (const candidate of [base, `${base}.html`, path.join(base, "index.html")]) {
    try {
      if ((await fs.stat(candidate)).isFile()) return candidate;
    } catch { /* try the next Pages-style candidate */ }
  }
  return null;
}

/** Serve `root` under `basePath` on loopback; `/` outside the base path is a blank page. */
export async function startStaticDemoServer(root, basePath) {
  const absRoot = path.resolve(root);
  const server = http.createServer(async (req, res) => {
    const { pathname } = new URL(req.url ?? "/", "http://127.0.0.1");
    // Next fetches the base route's RSC payload as `<base>.txt`; docs.yml places index.txt there too.
    if (pathname === `${basePath}.txt`) {
      res.writeHead(200, { "content-type": "text/plain" }).end(await fs.readFile(path.join(absRoot, "index.txt")));
      return;
    }
    if (!pathname.startsWith(`${basePath}/`) && pathname !== basePath) {
      res.writeHead(pathname === "/" ? 200 : 404, { "content-type": "text/html" }).end("<!doctype html><title>blank</title>");
      return;
    }
    const file = await resolveFile(absRoot, pathname.slice(basePath.length) || "/");
    if (!file) {
      const notFound = await fs.readFile(path.join(absRoot, "404.html")).catch(() => Buffer.from("not found"));
      res.writeHead(404, { "content-type": "text/html" }).end(notFound);
      return;
    }
    res.writeHead(200, { "content-type": TYPES[path.extname(file)] ?? "application/octet-stream" });
    res.end(await fs.readFile(file));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  return { origin: `http://127.0.0.1:${port}`, close: () => new Promise((resolve) => server.close(resolve)) };
}
