import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import ts from "typescript";
import { expect, it } from "vitest";

/** Native anchors do not receive Next's basePath, unlike next/link. */
it("never emits unprefixed native anchors for internal application routes", () => {
  const offenders: string[] = [];
  function inspect(directory: string) {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const file = path.join(directory, entry.name);
      if (entry.isDirectory()) { inspect(file); continue; }
      if (!file.endsWith(".tsx")) continue;
      const source = ts.createSourceFile(file, readFileSync(file, "utf8"), ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
      function visit(node: ts.Node) {
        if ((ts.isJsxOpeningElement(node) || ts.isJsxSelfClosingElement(node)) && node.tagName.getText(source) === "a") {
          const href = node.attributes.properties.find(attribute => ts.isJsxAttribute(attribute) && attribute.name.getText(source) === "href");
          if (href && /^href=(?:["']\/(?!\/)|\{`\/(?!\/))/.test(href.getText(source))) {
            offenders.push(`${file}:${source.getLineAndCharacterOfPosition(href.pos).line + 1}`);
          }
        }
        ts.forEachChild(node, visit);
      }
      visit(source);
    }
  }
  const root = path.resolve(__dirname, "..");
  inspect(path.join(root, "app"));
  inspect(path.join(root, "components"));
  expect(offenders).toEqual([]);
});
