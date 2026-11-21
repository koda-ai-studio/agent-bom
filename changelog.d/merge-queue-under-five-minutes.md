### CI

- The merge queue runs the full suite in 16 Python shards, four Postgres partitions and eight browser shards, sized to merge in about five minutes. Each Python shard collects the test root once and keeps only its modules, because passing hundreds of module paths made pytest re-collect the test package for every path (90-170 s a shard). The demo-estate bootstrap tests are split across four modules so their per-test seeds spread over runners; every test keeps its fixture and assertions.
