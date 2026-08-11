"""
e2e: a query's rcode/latency land in the stats_periodic period it was
SENT in, not the period its (possibly delayed) response arrives in.

Not randomized: correctness depends on exact packet position. Query B
(packet #129) targets period4, not period3, so periods 2-3 -- expected
empty -- exist with margin before the process could shut down.
"""
import pathlib
import sys

import dns.message
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from ans import run_in_subprocess  # noqa: E402
from e2e_common import (  # noqa: E402
    TESTS_DIR,
    get_stats_periodic,
    merge_stats,
    read_records,
    run_replay,
)
from tcpdns2pcap import pcap_global_header, write_packet_record  # noqa: E402

FILLER_PACKETS = 127  # dnsjit batch size (128) minus query A

# tests/latency_{udp,tcp}.toml bucket indices
UNDER_100MS, UNDER_300MS, UNDER_600MS, UNDER_1000MS, UNDER_1500MS, UNDER_2000MS, TIMED_OUT = range(7)

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
        for i in range(FILLER_PACKETS):  # #2..#128 filler
            add_query("rcode0.test.", 0, 10_000 + i)
        add_query("rcode0.test.", 3, 900_000)  # #129 query B
        add_query("rcode0.test.", 4, 0)  # #130 filler

    return pcap_path


@pytest.mark.parametrize("protocol", ["udp", "tcp"])
def test_replay_periods(protocol, tmp_path):
    pcap_path = _build_pcap(tmp_path)

    config = TESTS_DIR / f"latency_{protocol.lower()}.toml"
    outdir = tmp_path / "out"
    with run_in_subprocess() as port:
        run_replay(config, pcap_path, port, outdir)

    sender = protocol.upper()
    merged_path = merge_stats(outdir, sender, tmp_path)
    records = read_records(merged_path)
    periodic = get_stats_periodic(records)

    assert len(periodic) >= 4
    period1, period2, period3 = periodic[:3]

    assert period1["queries"] == FILLER_PACKETS + 1
    assert period1["responses"] == FILLER_PACKETS + 1
    assert period1["timeouts"] == 0
    assert period1["discarded"] == 0
    assert period1["response_rcodes"] == {"NOERROR": FILLER_PACKETS + 1}
    buckets = period1["response_latency"]["bucket_counts"]
    fast_buckets = (UNDER_100MS, UNDER_300MS, UNDER_600MS, UNDER_1000MS)
    assert sum(buckets[i] for i in fast_buckets) == FILLER_PACKETS
    assert buckets[UNDER_1500MS] == 1  # query A
    assert buckets[UNDER_2000MS] == 0
    assert buckets[TIMED_OUT] == 0

    for period, expected_ongoing in ((period2, 1), (period3, 0)):
        assert period["queries"] == 0
        assert period["responses"] == 0
        assert period["timeouts"] == 0
        assert period["discarded"] == 0
        assert period["response_rcodes"] == {}
        assert period["response_latency"]["bucket_counts"] == EMPTY_BUCKET_COUNTS
        assert period["ongoing"] == expected_ongoing
