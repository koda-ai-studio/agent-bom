### CI
- The read-only demo's build and browser checks run on pull requests that touch the UI and in the merge queue, not only after merge, so a change that breaks the published demo fails before it lands; only a push to main deploys it.
- The demo's selected-path check expects the CVE as the path's target hop with the finding badge on its package, matching the compact investigation canvas.

### Fixed
- The read-only demo answers node finding counts for any hop list a page settles on from one table of every node, instead of only the hop lists recorded at build time.
