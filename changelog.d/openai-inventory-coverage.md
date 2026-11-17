### Fixed

- OpenAI discovery no longer calls the retired Assistants API. It inventories completed fine-tuning jobs and explicitly reports the unsupported application-inventory coverage. Partial pagination retains collected jobs, detects malformed pages and repeated cursors, and reports denied, throttled, or unavailable reads without provider diagnostics.
