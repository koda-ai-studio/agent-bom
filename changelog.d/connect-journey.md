### Fixed

- `agent-bom connect aws|azure|gcp|snowflake` no longer points a pip install at repository paths it does not have: recipes link to the installed release's source, and the Terraform path is one `terraform init -from-module=...` command that works in an empty directory.
- `agent-bom connect` now recognises a normal CLI login (`~/.aws/credentials` or `~/.aws/config`, `az login`, `gcloud auth application-default login`) instead of reporting "No credentials detected" when only environment variables are unset.
