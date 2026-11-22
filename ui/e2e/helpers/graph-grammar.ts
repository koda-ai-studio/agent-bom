import type { Page } from "@playwright/test";
import { graphGrammarExpression } from "../../scripts/graph-visual-audit.mjs";

/** The capture gate's grammar audit on the current frame, judged with the shared caption geometry; `{}` means it passes. */
export async function graphGrammarViolations(page: Page, options: Record<string, number> = {}): Promise<Record<string, unknown>> {
  return page.evaluate(graphGrammarExpression(options)) as Promise<Record<string, unknown>>;
}
