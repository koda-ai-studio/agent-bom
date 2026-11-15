### Fixed
- Graph connections of different relationship types that leave or enter the same card no longer share one line: each type runs on its own parallel lane, so a "Uses" bundle and a "Can Access" link from one agent stay apart instead of interleaving their dashes.
- Lines that cross one column gap toward different cards turn in separate channels, so several sources feeding two targets no longer merge into one vertical trunk that hides which source feeds which target.
- In the exposure flow, an account or other container that holds an entry point sits in a column before what it contains, so its links run left to right instead of looping around the column.
- The "Image inventory" occurrence chip on a container card stays on one line.
- The graph focus, dimming and cluster-pill styles moved from an inline styled-jsx block into the global stylesheet, removing that runtime from the graph pages (about 16 KiB of client JavaScript).
