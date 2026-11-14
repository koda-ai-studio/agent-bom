/**
 * Which demo-data reads had no sample answer, and which pages they leave incomplete.
 *
 * A page is incomplete whenever it needs a path file that has no answer, including
 * when an earlier page already found that path unanswered: the second page would
 * otherwise be published as "in the demo" and render its error state.
 */
export function createStaticDemoCoverage() {
  const unanswered = new Set();
  const missing = new Set();
  const incomplete = new Set();
  const markPage = (exactQuery, apiPath, route) => {
    // Exact-query files are optional; the path file behind them decides.
    if (exactQuery) return;
    missing.add(apiPath.split("?")[0]);
    incomplete.add(route);
  };
  return {
    unanswered,
    missing,
    incomplete,
    /** True when this key already has no answer; the page asking is marked incomplete. */
    alreadyUnanswered(key, { exactQuery, apiPath, route }) {
      if (!unanswered.has(key)) return false;
      markPage(exactQuery, apiPath, route);
      return true;
    },
    noAnswer(key, { exactQuery, apiPath, route }) {
      unanswered.add(key);
      markPage(exactQuery, apiPath, route);
    },
  };
}
