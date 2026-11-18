# Raw measurement data

Committed copies of the nightly metrics job's CSV output. CI artifacts expire
(90 days is set on the upload), so the permanent record lives here and is
diffable in review.

File names carry the CI run id: `handoff-metrics-<run-id>.csv`.

| File | CI run | Runner | Commit |
|---|---|---|---|
| `handoff-metrics-44283599775.csv` | [44283599775](https://github.com/cy1ingachref/HIMAN/actions/runs/44283599775) | ubuntu-26.04 | `c49b89a` |

Columns:

| Column | Meaning |
|---|---|
| `run` | 0-based run index within the job |
| `switch_ms` | the driver's measure of the switch |
| `total_ms` | wall clock for the whole handoff attempt |
| `replay_lag` | log events the target had not applied at the switch |
| `rolled_back` | whether the attempt rolled back |
| `rollback_cause` | the reason, empty when it did not |
| `owner_gap_ms` | longest owner-less interval (AC-2; must be 0) |
| `longest_step_gap_ms` | largest gap between consecutive steps across the switch |
| `normal_step_gap_ms` | median gap between steps by the same owner |

The summary tables with p50/p95 are in `docs/METRICS.md`. The generator is
`orchestrator/examples/handoff_metrics.rs`; `orchestrator/results/` stays
git-ignored because it is a working output directory.
