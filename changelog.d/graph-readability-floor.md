### Changed
- The selected attack path opens as the top row with its branches below (beside it on a phone), at a readable scale that uses the canvas width. Lines change rows only between layers, so none crosses a node's name, and lines fanning out of one node leave side by side. Each hop of the path names its relationship on the line, names wrap only at separators, and finding badges state the worst severity in words. Phones draw every node and scroll sideways instead of hiding branches. Choosing a path traces it once from entry to target, and layout changes on the investigation canvas move cards to their new places; both are skipped under reduced motion.
- A focused attack path on the investigation canvas opens framed on its hops at a legible scale instead of one oversized card.
- Investigation canvas cards are drawn at one compact size, spaced so no card, caption or metadata line overlaps another, with a line legend under the canvas. A path finding is named by its rule with the full title on hover, same-name servers are told apart by the client that uses each one, and the headline path count says it covers the whole snapshot.

### Fixed
- Flow-view lines no longer run along a neighbouring line or detour through other cards, and small MCP evidence flows space their rows for the tallest card.
- A graph link with an unknown view, flow, step or map view, or an unknown address under the graph routes, now shows a not-found state with links back to the graph instead of silently opening another view.
