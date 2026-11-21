### Fixed

- The suggested follow-up commands after `scan --push-url ... --push-api-key ...` now repeat the key as `"$AGENT_BOM_PUSH_API_KEY"` instead of dropping it, so running them no longer pushes without authentication. The key itself is still never printed.
