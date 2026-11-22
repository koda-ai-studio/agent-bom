### Changed
- The estate scope map opens on the ranked overview (the riskiest scope's recorded connections, with every scope one click away) when the whole map cannot be read at a legible zoom on the current screen; a Scope map control returns to the map, and a status line says when the map opens on part of the estate (#6386).
- A focused attack path reads as one left-to-right row in hop order (#6385).

### Fixed
- The estate scope map keeps a cluster ahead of the containers it hosts and keeps agents that share credentials or a server next to each other, so their links no longer loop round other cards (#6385).
- Links that meet one side of a card no longer share a line where a back link enters and a forward link leaves (#6385).
- The attack-path card hides a shared-server correlation when both agents' use of that server is already drawn (#6386).
- Node finding counts make one request per settled path instead of starting and cancelling one (#6385).
- Remediation labels its 0–10 package score Impact and shows the scale, so it is not read as the 0–100 path risk (#6386).
