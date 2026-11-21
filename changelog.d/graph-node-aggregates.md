### Added

- `GET /v1/graph/node-aggregates` returns the roll-up aggregate (issue count, worst severity, exposure count) and semantic layer for up to 25 named nodes, such as a selected attack path's hops; each value equals that node's own roll-up entry.

### Changed

- Roll-up entries, the drill-down node and attack-path view nodes carry `semantic_layer`.
