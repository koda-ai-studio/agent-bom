### Fixed
- Detect model API keys in plain ECS, Azure Container Apps, and Cloud Run environment values, including placeholders, without exposing values.
- Flag broad GCP project roles and Azure Owner/Contributor assignments at resource-group or subscription scope.
- Retire the missing-S3-encryption finding because AWS automatically applies SSE-S3 to new uploads; coalesce explicitly linked Azure account/public-container exposure findings.
