# HIMAN — Handoff metrics (AC-6)

Measured by `cargo run -p himan-orchestrator --example handoff_metrics`: 30
handoffs per cell against the real binaries, handoff requested mid-run.

The agents connect through a portable TCP proxy (`tests/common/proxy.rs`) that
adds one-way latency with jitter of a quarter of it. No `tc`, no root. The
orchestrator's HTTP API stays direct, so the numbers describe the agent links.

The sweep is 3 event-log sizes x 4 latencies x 30 handoffs = 360 runs. `steps` is
the scenario length, and each step is one event, so it is also the log size the
target shadow-replays.

This file records the runs CI produced. The metrics job is manual dispatch only
(`workflow_dispatch`, input `runs_per_cell`, default 10; use 30 for a final run)
and uploads the CSV as an
artifact (90-day retention); the committed copies in `docs/data/` are the
permanent record.

## Final sweep (360 runs, Linux, through the proxy)

| | |
|---|---|
| CI run | [44587040931](https://github.com/cy1ingachref/HIMAN/actions/runs/44587040931) |
| Job | `handoff metrics (manual)`, `workflow_dispatch` with `runs_per_cell=30` |
| Runner | `ubuntu-latest`, x86_64 |
| Branch / commit | `feat/phase2-planner` @ `df846ca` |
| Raw CSV | `docs/data/handoff-metrics-44587040931.csv` (360 rows) |

12 cells (3 log sizes x 4 one-way latencies) x 30 handoffs. Each cell is
`p50 / p95 / max` in ms; jitter is a quarter of the stated latency.

### 100 events

| Latency | Switch time (ms) | Longest inter-step gap (ms) | Rollback rate |
|---|---|---|---|
| 0 ms | 363 / 365 / 471 | 102 / 102 / 102 | 0.0% (0/30) |
| 25 ms | 484 / 489 / 489 | 101 / 102 / 102 | 0.0% (0/30) |
| 100 ms | 1115 / 1199 / 1207 | 102 / 102 / 102 | 0.0% (0/30) |
| 250 ms | 2388 / 2485 / 2727 | 101 / 102 / 102 | 0.0% (0/30) |

### 1000 events

| Latency | Switch time (ms) | Longest inter-step gap (ms) | Rollback rate |
|---|---|---|---|
| 0 ms | 364 / 365 / 473 | 102 / 102 / 102 | 0.0% (0/30) |
| 25 ms | 482 / 488 / 490 | 101 / 102 / 102 | 0.0% (0/30) |
| 100 ms | 1087 / 1183 / 1191 | 102 / 102 / 102 | 0.0% (0/30) |
| 250 ms | 2417 / 2478 / 2501 | 102 / 102 / 102 | 0.0% (0/30) |

### 10000 events

| Latency | Switch time (ms) | Longest inter-step gap (ms) | Rollback rate |
|---|---|---|---|
| 0 ms | 363 / 365 / 365 | 101 / 102 / 102 | 0.0% (0/30) |
| 25 ms | 481 / 487 / 488 | 101 / 102 / 102 | 0.0% (0/30) |
| 100 ms | 1125 / 1180 / 1196 | 102 / 103 / 103 | 0.0% (0/30) |
| 250 ms | 2386 / 2495 / 2503 | 101 / 102 / 102 | 0.0% (0/30) |

Pooled over all 360 runs: owner gap 0/0/0 ms, replay lag 0/0/0 events,
rollbacks 0 of 360.

### Comparison with the loopback baseline

The baseline (run 44283599775) was 30 runs at 100 events, direct loopback,
no proxy: switch p50/p95/max 375/376/377 ms.

- **0 ms through the proxy: 363/365/471.** The p50 is ~12 ms BELOW the
  baseline, not above: the proxy's own overhead is not measurable at this
  resolution, and the two runs are different CI instances, so a small shift
  in either direction is runner noise, not a proxy effect. The honest claim
  is "no measurable proxy overhead at p50", not "the proxy made it faster".
- **Latency scales as expected.** The switch is several round trips:
  +25 ms one-way adds ~120 ms (≈4-5 RTTs), +100 ms adds ~750 ms, +250 ms
  adds ~2025 ms. The relationship is linear in the added latency, which is
  what a multi-round-trip protocol should show.
- **Log size does not move the switch time.** 100 vs 10000 events differ by
  at most ~40 ms at p50 within the same latency — inside the run-to-run
  spread. Shadow replay of 10000 events completes within the step cadence;
  replay lag stayed 0 everywhere.
- **Variance.** Two outliers above 1.2x their cell p95, both in the 0 ms
  cells (471 and 473 ms vs ~365 typical, ~+108 ms). Every other cell's max
  is within ~10% of its p95. The 0 ms cells have the widest relative spread
  (stdev ~21-23 ms vs ~4 ms at 25 ms) because there is no added latency to
  dominate scheduler noise. No cell is flaky in the correctness sense:
  0 rollbacks, 0 owner gap, 0 replay lag in all 360 runs.
- **No regression.** Nothing in the sweep is worse than the baseline beyond
  runner noise, and the correctness invariants held in every run.

What this does NOT show: behavior under packet loss (the proxy's loss knob
exists but the sweep runs 0% loss), real WAN jitter beyond the modeled
quarter-latency jitter, or handoff under concurrent load. Those are future
measurements, not claims.

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
