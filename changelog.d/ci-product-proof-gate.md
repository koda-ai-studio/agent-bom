### Fixed
- Require product-proof captures alongside UI checks before merge, retaining failure diagnostics without publishing generated screenshots.
- A product-proof capture no longer fails on an API read the page superseded (aborted) when a later read of the same endpoint answered; an endpoint that never answered still fails the capture.
