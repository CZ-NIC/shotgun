"""response_latency.bucket_counts accounting."""

from bisect import bisect_right
from collections import Counter

import pytest

from ans import run_in_subprocess
from common import (
    build_pcap,
    get_stats_sum,
    merge_stats,
    read_records,
    run_replay,
    select_expected_fields,
)
from testconfigs import PROFILES, make_config

# Midpoint delays leave scheduling margin; 2000 ms forces the timeout bucket.
BUCKET_TARGETS = [50, 200, 450, 800, 1250, 1750, 2000]


@pytest.mark.parametrize("protocol", ["udp", "tcp"])
def test_replay_latency_buckets(protocol, tmp_path):
    qnames = []
    boundaries = PROFILES["latency"]["*"]["latency_bucket_boundaries"]
    expected = {
        "queries": 0,
        "responses": 0,
        "timeouts": 0,
        "discarded": 0,
        "response_rcodes": Counter(),
        "response_latency": {"bucket_counts": [0] * (len(boundaries) + 1)},
    }

    def add_queries(delay_ms, count):
        bucket = bisect_right(boundaries, delay_ms)
        timed_out = bucket == len(boundaries)
        instruction = "timeout" if timed_out else f"delay{delay_ms}"
        qnames.extend([f"{instruction}.test."] * count)
        expected["queries"] += count
        expected["response_latency"]["bucket_counts"][bucket] += count
        if timed_out:
            expected["timeouts"] += count
        else:
            expected["responses"] += count
            expected["response_rcodes"]["NOERROR"] += count

    for i, delay_ms in enumerate(BUCKET_TARGETS):
        add_queries(delay_ms, i + 1)
    assert all(expected["response_latency"]["bucket_counts"])

    pcap_path = build_pcap(qnames, tmp_path)

    outdir = tmp_path / "out"
    config, sender = make_config(tmp_path, "latency", protocol)
    with run_in_subprocess() as port:
        run_replay(config, pcap_path, port, outdir)

    merged_path = merge_stats(outdir, sender, tmp_path)
    records = read_records(merged_path)
    stats_sum = get_stats_sum(records)

    # RCODE entries are counters; unexpected codes must still fail the test.
    assert stats_sum["response_rcodes"] == expected["response_rcodes"]
    got = select_expected_fields(stats_sum, expected)
    assert got == expected
