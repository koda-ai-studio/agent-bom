### Fixed
- An API process no longer aborts (`FATAL: exception not rethrown`, SIGABRT) or crashes (SIGSEGV) at exit on Python 3.11-3.13 when a push commit has just started an exec-read, roll-up, reachability or posture warm-up. At exit the process now refuses new warm-ups, lets a running one finish its current step and waits at most 10 s, instead of leaving a daemon thread inside native validation code while the interpreter finalizes. A current-graph rebuild queued after the build pool has shut down is skipped quietly instead of logging a failed commit hook.

### Performance
- On glibc, the API process now limits malloc to two arenas (an operator's `MALLOC_ARENA_MAX` still wins). Freed heap held per thread made up about 460 MiB of a 1.75-1.9 GiB peak on the 200-agent workflow profile; peak RSS fell from 1,850 / 1,927 MiB to 1,435 / 1,477 MiB (cold / warm) with identical findings and fewer CPU-seconds. The Alpine API image (musl) is unchanged.

### CI
- The nightly workflow resource benchmark no longer charges the CLI's own work to the API process it measures: the scan child now parses the report and builds the push body, as the collector host does.
- The two-replica Postgres profile runs on a freshly migrated database of its own. After the single-API profile in the shared database its tenant carried three estates instead of two, which put each replica at 1.8-2.1 GiB rather than 1.1-1.3 GiB.
