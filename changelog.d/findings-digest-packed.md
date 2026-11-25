### Changed
- **Less memory and shorter pauses while scans land.** The findings view's per-scan cache now holds each scan's projected rows as compressed JSON instead of live Python objects. In a 22-scan, 500-agent test estate:
  - the API's resident memory after warm-up fell from 4.2 GiB to 2.9 GiB
  - after an ingest, the number of objects every full garbage collection walks fell from 12.5 million to 2.8 million
  - the first findings read after a new scan stays near one second

  Before, those collections paused every request, including `/health`, for seconds while a scan was ingested. Each read also now gets rows of its own, so nothing a reader does to a row can reach the cache.
