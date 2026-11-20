### Fixed

- AWS, Azure and GCP CIS checks now report ERROR instead of PASS when a resource read fails for a reason other than a permission denial, such as throttling or a provider outage, and CIS evidence names only the error type and provider code instead of the raw provider message.
- Azure multi-subscription inventory now logs a sanitized warning when no credential can be created instead of returning an empty result silently.
