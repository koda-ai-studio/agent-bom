### CI
- The release run's post-release pin job checks out, pushes and opens its PR with a `RELEASE_PINS_TOKEN` secret when one is configured, since the built-in token may not update the reusable workflow's pin; without the secret it behaves as before.
