# HIMAN — Handoff metrics (AC-6)

Measured by `cargo run -p himan-orchestrator --example handoff_metrics`: 30
handoffs per cell against the real binaries, handoff requested mid-run.

The agents connect through a portable TCP proxy (`tests/common/proxy.rs`) that
adds one-way latency with jitter of a quarter of it. No `tc`, no root. The
orchestrator's HTTP API stays direct, so the numbers describe the agent links.

The sweep is 3 event-log sizes x 4 latencies x 30 handoffs = 360 runs. `steps` is
the scenario length, and each step is one event, so it is also the log size the
target shadow-replays.

This file records the runs CI produced. The nightly job uploads the CSV as an
artifact (90-day retention); the committed copies in `docs/data/` are the
permanent record.

## Sweep (pending the next nightly run)

The extended sweep was added in this branch and has not yet run on CI. The
table below is the shape it produces; the numbers are filled in from the run.

| Latency | Switch time p50/p95/max (ms) | Longest inter-step gap p50/p95/max (ms) | Rollback rate |
|---|---|---|---|
| 0 ms | pending | pending | pending |
| 25 ms | pending | pending | pending |
| 100 ms | pending | pending | pending |
| 250 ms | pending | pending | pending |

One table per log size (100, 1000, 10000 events).

**Local smoke test** (reduced sweep: 2 runs, 100 events, Windows, this machine):

| Latency | Switch time (ms) | Owner gap | Rollbacks |
|---|---:|---:|---:|
| 0 ms | 352, 351 | 0 | 0 of 2 |
| 100 ms | 1244, 1119 | 0 | 0 of 2 |

The proxy demonstrably moves the number: ~351 ms at 0 ms becomes ~1180 ms at
100 ms one-way, which is the expected order (the switch is several round trips).
Owner gap stayed 0 and nothing rolled back. This is a smoke test, not the
measurement — 2 runs is not a distribution.

## Baseline run (loopback, before the proxy)

| | |
|---|---|
| CI run | [44283599775](https://github.com/cy1ingachref/HIMAN/actions/runs/44283599775) |
| Job | `handoff metrics (nightly)` (ID 134730420283), 9m49s |
| Runner | `ubuntu-latest` (ubuntu-26.04), x86_64 |
| Branch / commit | `feat/phase3-redteam-metrics` @ `c49b89a` |
| Raw CSV | `docs/data/handoff-metrics-44283599775.csv` |

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
