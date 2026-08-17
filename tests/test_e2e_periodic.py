"""
e2e: a query's rcode/latency land in the stats_periodic period it was
SENT in, not the period its (possibly delayed) response arrives in.

Not randomized: correctness depends on exact packet position. Query B
(packet #129) targets period4, not period3, so periods 2-3 -- expected
empty -- exist with margin before the process could shut down.

doh included: period1's 128-query burst exceeds HTTP/2's default stream
limit, but a query's period is fixed at dnssim packet dequeueing time
regardless of when its response arrives, so the resulting delay doesn't
corrupt attribution.
"""

import pathlib
import sys

import dns.message
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from e2e_common import (  # noqa: E402
    TESTS_DIR,
    get_stats_periodic,
    merge_stats,
    read_records,
    run_replay_for,
    run_server,
)
from tcpdns2pcap import pcap_global_header, write_packet_record  # noqa: E402

BATCH = 128  # dnsjit's filter.timing:realtime() batch size
PERIOD1_FILLERS = BATCH - 2  # minus query A and timeout query T1
PERIOD2_FILLERS = BATCH - 1  # minus timeout query T2

# tests/latency_{udp,tcp}.toml bucket indices
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


def _build_pcap(tmp_path) -> pathlib.Path:
    pcap_path = tmp_path / "queries.pcap"
    with open(pcap_path, "wb") as f:
        f.write(pcap_global_header())

        qid = 1

        def add_query(qname, ts_sec, ts_usec):
            nonlocal qid
            q = dns.message.make_query(qname, "A")
            q.id = qid
            write_packet_record(f, q.to_wire(), ts_sec, ts_usec)
            qid += 1

        add_query("delay1250.test.", 0, 0)  # #1 query A
        add_query("timeout.test.", 0, 5_000)  # #2 query T1
        for i in range(PERIOD1_FILLERS):  # #3..#128 filler
            add_query("rcode0.test.", 0, 10_000 + i)

        add_query("timeout.test.", 1, 500_000)  # #129 query T2
        for i in range(PERIOD2_FILLERS):  # #130..#256 filler
            add_query("rcode0.test.", 1, 510_000 + i)

        add_query("rcode0.test.", 3, 900_000)  # #257 query C

        add_query("rcode0.test.", 4, 0)  # #258 filler

    return pcap_path


@pytest.mark.parametrize("protocol", ["udp", "tcp", "dot", "doh", "doq"])
def test_replay_periods(protocol, tmp_path):
    pcap_path = _build_pcap(tmp_path)

    config = TESTS_DIR / f"latency_{protocol.lower()}.toml"
    outdir = tmp_path / "out"
    with run_server(protocol, tmp_path) as (port, extra_port):
        run_replay_for(protocol, config, pcap_path, port, extra_port, outdir)

    sender = protocol.upper()
    merged_path = merge_stats(outdir, sender, tmp_path)
    records = read_records(merged_path)
    periodic = get_stats_periodic(records)

    assert len(periodic) >= 4
    period1, period2, period3 = periodic[:3]

    fast_buckets = (UNDER_100MS, UNDER_300MS, UNDER_600MS, UNDER_1000MS)

    assert period1["ongoing"] == 0
    assert period1["queries"] == PERIOD1_FILLERS + 2  # + query A + query T1
    assert period1["responses"] == PERIOD1_FILLERS + 1  # T1 never answered
    assert period1["timeouts"] == 1
    assert period1["discarded"] == 0
    assert period1["response_rcodes"] == {"NOERROR": PERIOD1_FILLERS + 1}
    buckets1 = period1["response_latency"]["bucket_counts"]
    assert sum(buckets1[i] for i in fast_buckets) == PERIOD1_FILLERS
    assert buckets1[UNDER_1500MS] == 1  # query A
    assert buckets1[UNDER_2000MS] == 0
    assert buckets1[TIMED_OUT] == 1  # query T1

    assert period2["ongoing"] == 2  # query A, query T1 -- both still pending
    assert period2["queries"] == PERIOD2_FILLERS + 1  # + query T2
    assert period2["responses"] == PERIOD2_FILLERS  # T2 never answered
    assert period2["timeouts"] == 1
    assert period2["discarded"] == 0
    assert period2["response_rcodes"] == {"NOERROR": PERIOD2_FILLERS}
    buckets2 = period2["response_latency"]["bucket_counts"]
    assert sum(buckets2[i] for i in fast_buckets) == PERIOD2_FILLERS
    assert buckets2[UNDER_1500MS] == 0
    assert buckets2[UNDER_2000MS] == 0
    assert buckets2[TIMED_OUT] == 1  # query T2

    # ongoing not checked: T1's timeout coincides with period3's creation tick
    assert period3["queries"] == 0
    assert period3["responses"] == 0
    assert period3["timeouts"] == 0
    assert period3["discarded"] == 0
    assert period3["response_rcodes"] == {}
    assert period3["response_latency"]["bucket_counts"] == EMPTY_BUCKET_COUNTS
