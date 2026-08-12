"""
e2e: TCP connection reuse driven by idle_timeout_s (conn_reuse_idle0.toml,
conn_reuse_idle10.toml), checking conn_info in the merged stats_sum.

idle_timeout_s only governs closing once a connection is truly idle (no
queued or in-flight queries) -- it does not force one query per connection.
A query sent while a prior one on the same conn is still awaiting its
response still pipelines onto it, even with idle_timeout_s=0.

Not randomized: dnsjit's filter.timing:realtime() only re-checks the pcap
clock once per 128-packet batch (BATCH below), dispatching each batch back
to back with no internal pacing. So packet position controls timing, not
just the pcap timestamps: batch1 (query #1 delayed 500ms + 127 fillers, all
fired ~simultaneously) proves same-connection pipelining regardless of
idle_timeout_s; batch2 (query #129, 2s later) proves whether that
connection is still around to be reused, or had to be reopened.
"""
import pathlib
import sys

import dns.message

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from ans import run_in_subprocess  # noqa: E402
from e2e_common import (  # noqa: E402
    TESTS_DIR,
    get_stats_sum,
    merge_stats,
    read_records,
    run_replay,
)
from tcpdns2pcap import pcap_global_header, write_packet_record  # noqa: E402

BATCH = 128  # dnsjit's filter.timing:realtime() batch size
NUM_QUERIES = 2 * BATCH


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

        add_query("delay500.test.", 0, 0)  # #1: still in flight when...
        for i in range(BATCH - 1):  # #2..#128: ...these pipeline onto its conn
            add_query("rcode0.test.", 0, 1 + i)

        for i in range(BATCH):  # #129..#256, 2s later (well under idle_timeout_s=10)
            add_query("rcode0.test.", 2, i)

    return pcap_path


def test_conn_reuse_idle0_single_query(tmp_path):
    # Baseline: one query, one connection, closed right after -- no batch
    # trick needed since there's nothing to pipeline with or reuse against.
    pcap_path = tmp_path / "queries.pcap"
    with open(pcap_path, "wb") as f:
        f.write(pcap_global_header())
        q = dns.message.make_query("rcode0.test.", "A")
        q.id = 1
        write_packet_record(f, q.to_wire(), 0, 0)
    config = TESTS_DIR / "conn_reuse_idle0.toml"

    outdir = tmp_path / "out"
    with run_in_subprocess() as port:
        run_replay(config, pcap_path, port, outdir)

    merged_path = merge_stats(outdir, "TCP", tmp_path)
    stats_sum = get_stats_sum(read_records(merged_path))

    assert stats_sum["queries"] == 1
    assert stats_sum["responses"] == 1
    assert stats_sum["timeouts"] == 0
    assert stats_sum["discarded"] == 0
    assert stats_sum["conn_info"]["type"] == "tcp"
    assert stats_sum["conn_info"]["handshakes"] == 1
    assert stats_sum["conn_info"]["handshakes_failed"] == 0
    assert stats_sum["conn_active"] == 0  # closed once idle, before run ended


def test_conn_reuse_idle0(tmp_path):
    pcap_path = _build_pcap(tmp_path)
    config = TESTS_DIR / "conn_reuse_idle0.toml"

    outdir = tmp_path / "out"
    with run_in_subprocess() as port:
        run_replay(config, pcap_path, port, outdir)

    merged_path = merge_stats(outdir, "TCP", tmp_path)
    stats_sum = get_stats_sum(read_records(merged_path))

    assert stats_sum["queries"] == NUM_QUERIES
    assert stats_sum["responses"] == NUM_QUERIES
    assert stats_sum["timeouts"] == 0
    assert stats_sum["discarded"] == 0
    assert stats_sum["conn_info"]["type"] == "tcp"
    # batch1 pipelines onto 1 conn despite idle_timeout_s=0; batch2 arrives
    # 2s later, long after batch1's conn went idle and closed -> new conn.
    assert stats_sum["conn_info"]["handshakes"] == 2
    assert stats_sum["conn_info"]["handshakes_failed"] == 0


def test_conn_reuse_idle10(tmp_path):
    pcap_path = _build_pcap(tmp_path)
    config = TESTS_DIR / "conn_reuse_idle10.toml"

    outdir = tmp_path / "out"
    with run_in_subprocess() as port:
        run_replay(config, pcap_path, port, outdir)

    merged_path = merge_stats(outdir, "TCP", tmp_path)
    stats_sum = get_stats_sum(read_records(merged_path))

    assert stats_sum["queries"] == NUM_QUERIES
    assert stats_sum["responses"] == NUM_QUERIES
    assert stats_sum["timeouts"] == 0
    assert stats_sum["discarded"] == 0
    assert stats_sum["conn_info"]["type"] == "tcp"
    # batch1's conn is still within its 10s idle window when batch2 arrives
    # 2s later -> reused, one handshake for the whole run.
    assert stats_sum["conn_info"]["handshakes"] == 1
    assert stats_sum["conn_info"]["handshakes_failed"] == 0
