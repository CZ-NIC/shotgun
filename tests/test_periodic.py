"""responses and timeouts belong to the period in which dnssim created the request."""

from bisect import bisect_right
from collections import Counter
import pathlib

import dns.message
import pytest

from ans import run_in_subprocess
from common import (
    get_stats_periodic,
    merge_stats,
    read_records,
    run_replay,
)
from testconfigs import PROFILES, make_config
from tcpdns2pcap import pcap_global_header, write_packet_record

FILLER_PACKETS = 127  # dnsjit batch size (128) minus query A

# the "latency" profile bucket indices
(
    UNDER_100MS,
    UNDER_300MS,
    UNDER_600MS,
    UNDER_1000MS,
    UNDER_1500MS,
    UNDER_2000MS,
    TIMED_OUT,
) = range(7)

EMPTY_BUCKET_COUNTS = [0] * 7


def _build_pcap(tmp_path) -> tuple[pathlib.Path, list[dict]]:
    pcap_path = tmp_path / "queries.pcap"
    expected_periods = [
        {
            "queries": 0,
            "responses": 0,
            "timeouts": 0,
            "discarded": 0,
            "response_rcodes": Counter(),
            "response_latency": {"bucket_counts": EMPTY_BUCKET_COUNTS.copy()},
        }
        for _ in range(4)
    ]
    with open(pcap_path, "wb") as f:
        f.write(pcap_global_header())

        qid = 1

        def add_query(ts_sec, ts_usec, delay_ms):
            nonlocal qid
            # Capture starts at zero; each pacing batch stays within one second.
            expected = expected_periods[ts_sec]
            bucket = bisect_right(
                PROFILES["latency"]["*"]["latency_bucket_boundaries"], delay_ms
            )
            instruction = "timeout" if bucket == TIMED_OUT else f"delay{delay_ms}"
            qname = f"{instruction}.test."
            q = dns.message.make_query(qname, "A")
            q.id = qid
            write_packet_record(f, q.to_wire(), ts_sec, ts_usec)
            qid += 1

            expected["queries"] += 1
            expected["response_latency"]["bucket_counts"][bucket] += 1
            if bucket == TIMED_OUT:
                expected["timeouts"] += 1
            else:
                expected["responses"] += 1
                expected["response_rcodes"]["NOERROR"] += 1

        # Period 1: A responds during period 2.
        add_query(0, 0, delay_ms=1250)  # query 1 (A)
        for i in range(FILLER_PACKETS):  # queries 2-128: immediate responses
            add_query(0, 10_000 + i, delay_ms=0)
        # A is still ongoing at the start of period 2.
        expected_periods[1]["ongoing"] = 1
        # Period 3 is empty and A has completed.
        expected_periods[2]["ongoing"] = 0
        # Send B late in period 4, with a margin before replay finishes.
        add_query(3, 900_000, delay_ms=0)  # query 129 (B)

    return pcap_path, expected_periods[:3]


@pytest.mark.parametrize("protocol", ["udp", "tcp"])
def test_replay_periods(protocol, tmp_path):
    pcap_path, expected_periods = _build_pcap(tmp_path)

    config, sender = make_config(tmp_path, "latency", protocol)
    outdir = tmp_path / "out"
    with run_in_subprocess() as port:
        run_replay(config, pcap_path, port, outdir)

    merged_path = merge_stats(outdir, sender, tmp_path)
    records = read_records(merged_path)
    periodic = get_stats_periodic(records)

    assert len(periodic) >= 4
    for period, expected_period in zip(periodic, expected_periods):
        actual = {field: period[field] for field in expected_period}
        actual["response_latency"] = {
            "bucket_counts": period["response_latency"]["bucket_counts"]
        }
        expected = {
            **expected_period,
            "response_latency": {
                "bucket_counts": expected_period["response_latency"]["bucket_counts"]
            },
        }
        if expected["queries"]:
            # Fast responses can fall anywhere in the first four buckets.
            for record in (actual, expected):
                buckets = record["response_latency"]["bucket_counts"]
                record["response_latency"]["bucket_counts"] = [
                    sum(buckets[:UNDER_1500MS]),
                    *buckets[UNDER_1500MS:],
                ]
        assert actual == expected
