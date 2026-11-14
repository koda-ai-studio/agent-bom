### Fixed
- An API process no longer aborts (`FATAL: exception not rethrown`, SIGABRT) or crashes (SIGSEGV) at exit on Python 3.11-3.13 when a push commit has just started an exec-read, roll-up, reachability or posture warm-up. At exit the process now refuses new warm-ups, lets a running one finish its current step and waits at most 10 s, instead of leaving a daemon thread inside native validation code while the interpreter finalizes. A current-graph rebuild queued after the build pool has shut down is skipped quietly instead of logging a failed commit hook.

### CI
- The nightly workflow resource benchmark no longer charges the CLI's own work to the API process it measures: the scan child now parses the report and builds the push body, as the collector host does, so the update/delete stage no longer carries about 480 MiB of client-side heap.
