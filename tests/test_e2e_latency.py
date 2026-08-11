"""
e2e: replay.py over UDP/TCP vs ans.py, checking response_latency.bucket_counts
accounting. Uses tests/latency_{udp,tcp}.toml, which set explicit wide
buckets ([100, 300, 600, 1000, 1500, 2000]ms) instead of the default
10ms-linear step, so bucket widths comfortably absorb loopback/scheduling
jitter.

Bucket i (0-indexed, 6 timed buckets + 1 timeout/overflow bucket) gets i+1
queries, mirroring test_e2e_rcodes.py's "RCODE N -> N+1 queries" idiom.
Each timed bucket's queries use ans.py's "delayN" instruction with a delay
picked at the bucket's midpoint (50-250ms margin from either edge -- far
more than loopback asyncio scheduling jitter). The overflow bucket uses
ans.py's "timeout" instruction (no response at all) instead of a delay near
2000ms: dnssim forces latency = timeout_ms for any unanswered request
(replay/dnssim/src/output/dnssim/common.c:227-229), so this is fully
deterministic with zero timing risk, unlike timing a delay at the edge.

Query order is shuffled (seed printed, override with SEED env var, same as
test_e2e_rcodes.py) -- final per-bucket counts don't depend on order, and
this exercises that responses aren't mismatched/misattributed by interleaving
different buckets' delays on the same connection.

This test relies on ans.py/asyncserver.py dispatching TCP responses
concurrently per connection (AsyncDnsServer._handle_tcp) -- otherwise
delays on the same persistent TCP connection would compound (query N's
observed latency = its own delay + every earlier same-connection query's
delay), corrupting bucket assignment. Confirmed empirically pre-fix and
post-fix with a raw-socket probe before this test was written.
"""
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from ans import run_in_subprocess  # noqa: E402
from e2e_common import (  # noqa: E402
    TESTS_DIR,
    build_pcap,
    get_stats_sum,
    merge_stats,
    read_records,
    run_replay,
    seeded_rng,
)

# (target delay in ms, None for the "timeout" instruction), one per bucket,
# in the same order as latency.toml's latency_bucket_boundaries plus the
# trailing overflow/timeout bucket.
BUCKET_TARGETS = [50, 200, 450, 800, 1250, 1750, None]


@pytest.mark.parametrize("protocol", ["udp", "tcp"])
def test_replay_latency_buckets(protocol, tmp_path):
    rng = seeded_rng()

    qnames = []
    for i, target in enumerate(BUCKET_TARGETS):
        instruction = "timeout" if target is None else f"delay{target}"
        qnames += [f"{instruction}.test."] * (i + 1)
    rng.shuffle(qnames)

    expected_bucket_counts = [i + 1 for i in range(len(BUCKET_TARGETS))]
    expected_timeouts = expected_bucket_counts[-1]
    total_queries = sum(expected_bucket_counts)
    expected_responses = total_queries - expected_timeouts

    pcap_path = build_pcap(qnames, tmp_path)

    outdir = tmp_path / "out"
    config = TESTS_DIR / f"latency_{protocol.lower()}.toml"
    with run_in_subprocess() as port:
        run_replay(config, pcap_path, port, outdir)

    sender = protocol.upper()
    merged_path = merge_stats(outdir, sender, tmp_path)
    records = read_records(merged_path)
    stats_sum = get_stats_sum(records)

    assert stats_sum["queries"] == total_queries
    assert stats_sum["responses"] == expected_responses
    assert stats_sum["timeouts"] == expected_timeouts
    assert stats_sum["discarded"] == 0
    assert stats_sum["response_rcodes"] == {"NOERROR": expected_responses}
    assert stats_sum["response_latency"]["bucket_counts"] == expected_bucket_counts
