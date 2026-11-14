Tiny synthetic projects for the eval-suite detection and safety-eval coverage
tests. Nothing here is executed: the scanner only reads these files. Agents
read their model-provider key from the environment by name; no key value is
committed.

- `promptfoo_redteam/` — a support agent with write tools, covered by a
  promptfoo config with a `redteam` section whose target is the agent's entry
  file, plus a promptfoo output file with recorded results.
- `deepeval_safety/` — a refund agent covered by a deepeval test that uses
  safety metrics on the agent's output.
- `uncovered_agent/` — an agent with write and execute tools whose only eval is
  a quality (RAG) eval. Its agent source is stored as `ops_agent.py.fixture` and
  copied to `ops_agent.py` by the tests, so a scan of this repository does not
  report the deliberately uncovered fixture agent.
