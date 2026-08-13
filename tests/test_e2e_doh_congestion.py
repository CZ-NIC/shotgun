"""
e2e: DoH burst that exceeds HTTP/2's default MAX_CONCURRENT_STREAMS=100.

dnsjit's filter.timing:realtime() dispatches 128 packets per pacing-clock
check with zero inter-packet delay (see test_e2e_periodic.py), so 128
same-connection queries arrive at dnssim as one synchronous burst. dnssim's
HTTP/2 client assumes the RFC 7540 default of 100 concurrent streams until
it reads an updated SETTINGS frame, so the last 28 queries get deferred
(CONGESTED) rather than sent. Regression test for the dnssim bug where the
CONGESTED->ACTIVE transition never resumed those deferred queries once
streams freed up (fixed in https2.c's resume_pending handling): without the
fix, this times out the last 28 queries instead of getting all 128 answered.

Also checks response_latency: ans.py answers immediately (no delayN), so
even the congestion-deferred queries -- resumed as soon as an earlier
stream closes, not held for a fixed retry interval -- should land in the
lowest bucket alongside the queries sent up front.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from e2e_common import (  # noqa: E402
    TESTS_DIR,
    build_pcap,
    get_stats_sum,
    merge_stats,
    read_records,
    run_replay_for,
    run_server,
)

QUERY_COUNT = 128


def test_doh_burst_past_max_concurrent_streams(tmp_path):
    qnames = ["rcode0.test."] * QUERY_COUNT
    pcap_path = build_pcap(qnames, tmp_path)
    config = TESTS_DIR / "doh_congestion.toml"
    outdir = tmp_path / "out"

    with run_server("doh", tmp_path) as (port, extra_port):
        run_replay_for("doh", config, pcap_path, port, extra_port, outdir)

    merged_path = merge_stats(outdir, "DOH", tmp_path)
    records = read_records(merged_path)
    stats_sum = get_stats_sum(records)

    assert stats_sum["queries"] == QUERY_COUNT
    assert stats_sum["responses"] == QUERY_COUNT
    assert stats_sum["timeouts"] == 0
    assert stats_sum["response_rcodes"] == {"NOERROR": QUERY_COUNT}
    assert stats_sum["response_latency"]["bucket_counts"] == [QUERY_COUNT, 0, 0]
