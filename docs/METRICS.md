# HIMAN — Handoff metrics (AC-6)

Measured by `cargo run -p himan-orchestrator --example handoff_metrics`: 30 runs
of the AC-1 scenario against the real binaries, handoff requested mid-run.

This file records the runs that CI produced, so a regression shows up as a
number that moved rather than a feeling. The nightly job uploads the CSV as an
artifact; the table below is committed so it is diffable in review.

## Latest run

| | |
|---|---|
| CI run | [44283599775](https://github.com/cy1ingachref/HIMAN/actions/runs/44283599775) |
| Job | `handoff metrics (nightly)` (ID 134730420283), 9m49s |
| Runner | `ubuntu-latest` (ubuntu-26.04), x86_64 |
| Branch / commit | `feat/phase3-redteam-metrics` @ `c49b89a` |
| Artifact | `handoff-metrics`, 815 B, id 14417463847 |

| Metric | p50 | p95 | Max |
|---|---:|---:|---:|
| switch time (ms) | 375 | 376 | 377 |
| total handoff time (ms) | 375 | 376 | 377 |
| replay lag (events) | 0 | 0 | 0 |
| owner gap (ms) | 0 | 0 | 0 |
| longest inter-step gap (ms) | 102 | 102 | 102 |
| normal inter-step gap (ms) | 102 | 102 | 102 |

Rollbacks: 0 of 30. Replay lag 0: the target had applied the whole checkpoint
before the switch in every run. Owner gap 0: no run had a window with no owner.

The longest inter-step gap equals the normal inter-step gap (102 ms). The
switch lands between steps, so the commit adds no measurable delay beyond the
scenario's own step cadence — the handoff is not the thing a user waits for.

## Earlier run (Windows, this machine)

Run at commit `f021486`, 30 runs, ~500 s:

| Metric | p50 | p95 | Max |
|---|---:|---:|---:|
| switch time (ms) | 350 | 362 | 365 |
| total handoff time (ms) | 350 | 362 | 365 |
| replay lag (events) | 0 | 0 | 0 |
| owner gap (ms) | 0 | 0 | 0 |
| longest inter-step gap (ms) | 108 | 111 | 117 |
| normal inter-step gap (ms) | 108 | 109 | 109 |

## Reading these numbers

- **switch time** — the driver's measure of the switch itself (prepare →
  commit → ack). 375 ms p50 on Linux.
- **total handoff time** — wall clock for the whole attempt. Equal to the switch
  time in these runs because nothing retried.
- **replay lag** — how much of the source's log the target had not applied when
  the switch happened. 0 means the shadow phase kept up.
- **owner gap** — the longest owner-less interval. This is the AC-2 number; a
  non-zero value is a correctness bug, not a performance one.
- **longest inter-step gap** — the largest gap between consecutive
  `step_issued` events where the owner changes, i.e. across the switch.
- **normal inter-step gap** — the median gap between steps by the same owner,
  i.e. the scenario's cadence.

The metric is a real-binary measurement: the orchestrator and both agents are
separate processes, so process startup, the WebSocket round trips and SQLite
are all in the number.

## Caveats

- 30 runs is a sample, not a bound. p95 here is close to p50 because the
  distribution is tight; a slower machine or a loaded CI runner will move all
  three columns together.
- The job runs on a shared GitHub runner, so absolute numbers are not
  comparable to the Windows run above — only the shape (0 lag, 0 gap, no
  rollback) is portable.
- The step cadence is set by the scenario's own delay, so the inter-step gap is
  dominated by that, not by the handoff.
