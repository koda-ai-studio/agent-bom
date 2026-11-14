### CI
- The merge queue runs the full Python suite in eight shards balanced by refreshed timings and starts a lone entry after one minute instead of five, so a queued pull request merges in about ten minutes instead of twenty-five.
- The graph check that no connection is drawn around the map holds each edge to its own endpoints. Above 80 nodes only on-screen nodes are drawn, so comparing edges with the leftmost drawn node failed whenever Fit all left the first column off screen.
