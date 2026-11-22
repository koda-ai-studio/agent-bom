import type { Page } from "@playwright/test";
import { auditGraphGrammar } from "../../scripts/graph-visual-audit.mjs";

/** The capture gate's grammar audit on the current frame; `{}` means it passes. */
export async function graphGrammarViolations(page: Page, options: Record<string, number> = {}): Promise<Record<string, unknown>> {
  return page.evaluate(auditGraphGrammar, options);
}
