# Test flakiness: what was fixed, what is left

Originally a note about `test_e2e_sigint.py` alone. That flake is fixed, and
so are several others found alongside it; what remains is a property of
running the suite at high parallelism rather than a bug.

## Fixed

- **`merge-data.py` rejected ragged period tails.** Threads tick their stats
  timers independently, so one could write a period the others never got to
  (seen: a 1 ms partial period carrying a whole batch of queries). Merging
  line by line demanded identical record counts and failed the whole merge,
  taking `replay.py` down with it. Merged per period now.
- **`shotgun.lua` sender threads quit with queries still queued.** The exit
  condition was an empty `try_get` next to a closed channel, but the ring's
  contents and the closed flag are published independently, so the flag
  could arrive first. dnsjit reported 640 packets dispatched while dnssim
  processed 512 — one client's whole batch silently lost. This one is a
  correctness bug in the tool, not just a test flake: a loaded run could
  under-report traffic and still look successful.
- **sigint queries could be split across a period boundary.** They were
  spread across each second, so a boundary could cut them in `batch_size`
  chunks (periods of 160 or 192 instead of 128). They are sent as
  sub-millisecond bursts now, which dnsjit hands over and dnssim dequeues in
  one piece.
- **The sigint interrupt was timed off the wrong clock.** It fired 3.5 s
  after `replay.py` was spawned, while periods are cut from whenever dnsjit
  finishes setting up; a slow start left only one period flushed. The test
  waits for the records it depends on now.

## Left: timing assertions under oversubscription

Failure counts per run of the whole suite (32 tests). Small samples — the
numbers say "much better", not "proven zero":

| mode | before | after |
|------|--------|-------|
| sequential | 4-5 (2 runs) | 0 (5 runs) |
| `-n 4` | not measured | 0 (5 of 6 runs; 1 run had 1) |
| `-n auto` (16 workers) | 8-11 (5 runs) | 4-5 (5 runs) |

The single `-n 4` failure predates the fix for a timed-out sigint wait
leaving its replay running, which competed with whatever ran next.

`-n auto` puts 16 pytest workers on 16 cores, each running an `ans.py`
server plus a `replay.py` with 3 dnssim threads — roughly 4x
oversubscription. What fails there is timing thresholds, not correctness:

- `test_e2e_latency.py` places responses in buckets whose edges sit 50-250 ms
  from the target delays. Contention pushes responses past an edge.
- `test_e2e_doh_congestion.py` fails only its latency histogram
  (`[9, 119, 0]` instead of `[128, 0, 0]`); every correctness assertion —
  all queries answered, no timeouts, right rcodes — still passes.
- `test_e2e_sigint.py` needs its interrupt to land mid-run. Under
  contention the run can instead finish first, and threads that shut down
  cleanly write the summary the test expects to be absent — observed as a
  merge of three thread files where two carried a `stats_sum` and one did
  not, which `merge-data.py` refuses (deliberately: merging a subset of the
  summaries would understate the totals).
- `test_e2e_periodic.py` checks `ongoing` at period boundaries, which moves
  when responses are delayed by contention. Seen once in three `-n 4` runs
  and once per five `-n auto` runs; the failing assertion was not captured,
  so the mechanism here is inferred rather than observed.

These thresholds are the point of those tests, so loosening them to make
`-n auto` green would remove the coverage. Run the suite sequentially or at
`-n 4` when the numbers matter.

`test_e2e_latency.py::test_replay_latency_buckets[doq]` fails at `-n auto`
more reliably than the other transports (5 runs out of 5). aioquic is pure
Python and the most CPU-hungry server path in the suite, so it is the first
to miss a deadline — consistent with contention, but not separately proven.

## Unresolved

Nothing outstanding with a reproduction. If `conn_recover` shows
`assert 512 == 640` again, that is the channel drain race and the fix above
did not cover it; the diagnostic is to compare dnsjit's
`processed N packets from input PCAP` against dnssim's `total processed`
in the same run.
