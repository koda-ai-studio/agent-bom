### Performance
- While a push rebuilds the current graph, current-estate graph reads (`/v1/graph` in every view, roll-up, search and incident-edge paging) answer at once from the last complete graph instead of waiting up to 50 ms for the rebuild, and a restarted or sibling API worker serves that graph too instead of waiting up to 2 s and answering 503. Each such response says `freshness: previous_generation` with `as_of`, the time its evidence was recorded, and never mixes the old and new graphs. Only a tenant with no complete graph yet waits for its first build. Reads that name a `scan_id` are unchanged: they read that recorded scan exactly.

### Changed
- `/v1/findings` adds `graph_freshness` (with `as_of`) while the graph is rebuilding, when graph reachability on the page is unassessed. The graph page shows "Updating graph · showing data from <time>" and Findings shows a matching note.
