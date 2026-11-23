### Fixed
- MCP image and MCP Registry publishing now follow a release whose artifacts all shipped even when a job that runs afterwards (the docs build or the post-release pins sync) fails. 0.115.6 shipped to PyPI, Docker Hub and GitHub, but its MCP image and registry entry were skipped because those two later jobs marked the whole Release run failed. A release that failed before publishing is still skipped, now with a notice, and an incomplete job list fails closed.
- The MCP Registry job publishes the `server.json` from the release commit, not from the tip of main.
