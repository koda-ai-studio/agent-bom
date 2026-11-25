### Fixed
- Required distribution freshness failures now fail the scheduled workflow after publishing diagnostic evidence.
- Successful adoption milestones require complete scans; concurrent processes record repeat use atomically and summaries aggregate in SQLite.

### Added
- Fresh-install qualification exercises default loopback authentication, server restart, and a second scan while checking retention of both graph snapshots.
