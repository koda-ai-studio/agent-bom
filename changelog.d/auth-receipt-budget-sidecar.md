### Fixed

- On SQLite, a slow authentication-failure receipt write no longer delays the failure count an authentication answer waits on, which could refuse a request with 503. Receipt budgets now live in their own sidecar file.
