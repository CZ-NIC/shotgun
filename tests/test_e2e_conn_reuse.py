"""
e2e: TCP/DoT connection reuse driven by idle_timeout_s (conn_reuse_idle0_*.toml,
conn_reuse_idle10_*.toml), checking conn_info in the merged stats_sum.

idle_timeout_s only governs closing once a connection is truly idle (no
queued or in-flight queries) -- it does not force one query per connection.
A query sent while a prior one on the same conn is still awaiting its
response still pipelines onto it, even with idle_timeout_s=0.

Not randomized: dnsjit's filter.timing:realtime() only re-checks the pcap
clock once per 128-packet batch (BATCH below), dispatching each batch back
to back with no internal pacing -- packet position controls timing, not
just the pcap timestamp.

test_conn_reuse_idle0_handshake_failed uses a whole batch of "terminate"
queries, not one mixed into plain ones: asyncserver.py dispatches responses
as tasks independent of read order, so a single terminate query would race
against the plain ones' responses; an all-terminate batch has no such
ordering dependency.
"""
import pathlib
import sys

import dns.message
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from e2e_common import (  # noqa: E402
    TESTS_DIR,
    get_stats_sum,
    merge_stats,
    read_records,
    run_replay,
    run_replay_for,
    run_server,
)
from tcpdns2pcap import pcap_global_header, write_packet_record  # noqa: E402

# dnssim's conn_info.type per protocol (dnssim.c:_output_dnssim_write_transport).
# doh (HTTPS2) reports "tls_conn", same as dot.
CONN_TYPE = {"tcp": "tcp", "dot": "tls_conn", "doh": "tls_conn"}

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


@pytest.mark.parametrize("protocol", ["tcp", "dot", "doh"])
def test_conn_reuse_idle0_single_query(protocol, tmp_path):
    # Baseline: one query, one connection, closed right after -- no batch
    # trick needed since there's nothing to pipeline with or reuse against.
    pcap_path = tmp_path / "queries.pcap"
    with open(pcap_path, "wb") as f:
        f.write(pcap_global_header())
        q = dns.message.make_query("rcode0.test.", "A")
        q.id = 1
        write_packet_record(f, q.to_wire(), 0, 0)
    config = TESTS_DIR / f"conn_reuse_idle0_{protocol}.toml"

    outdir = tmp_path / "out"
    with run_server(protocol, tmp_path) as (port, extra_port):
        run_replay_for(protocol, config, pcap_path, port, extra_port, outdir)

    sender = protocol.upper()
    merged_path = merge_stats(outdir, sender, tmp_path)
    stats_sum = get_stats_sum(read_records(merged_path))

    assert stats_sum["queries"] == 1
    assert stats_sum["responses"] == 1
    assert stats_sum["timeouts"] == 0
    assert stats_sum["discarded"] == 0
    assert stats_sum["conn_info"]["type"] == CONN_TYPE[protocol]
    assert stats_sum["conn_info"]["handshakes"] == 1
    assert stats_sum["conn_info"]["handshakes_failed"] == 0
    assert stats_sum["conn_active"] == 0  # closed once idle, before run ended


@pytest.mark.parametrize("protocol", ["tcp", "dot", "doh"])
def test_conn_reuse_idle0(protocol, tmp_path):
    pcap_path = _build_pcap(tmp_path)
    config = TESTS_DIR / f"conn_reuse_idle0_{protocol}.toml"

    outdir = tmp_path / "out"
    with run_server(protocol, tmp_path) as (port, extra_port):
        run_replay_for(protocol, config, pcap_path, port, extra_port, outdir)

    sender = protocol.upper()
    merged_path = merge_stats(outdir, sender, tmp_path)
    stats_sum = get_stats_sum(read_records(merged_path))

    assert stats_sum["queries"] == NUM_QUERIES
    assert stats_sum["responses"] == NUM_QUERIES
    assert stats_sum["timeouts"] == 0
    assert stats_sum["discarded"] == 0
    assert stats_sum["conn_info"]["type"] == CONN_TYPE[protocol]
    # batch1 pipelines onto 1 conn despite idle_timeout_s=0; batch2 arrives
    # 2s later, long after batch1's conn went idle and closed -> new conn.
    assert stats_sum["conn_info"]["handshakes"] == 2
    assert stats_sum["conn_info"]["handshakes_failed"] == 0


@pytest.mark.parametrize("protocol", ["tcp", "dot", "doh"])
def test_conn_reuse_idle0_handshake_failed(protocol, tmp_path):
    # 4 isolated (idle_timeout_s=0) connections, 2s apart: batch1, batch2
    # succeed. batch3 (all "terminate") completes its handshake, then kills
    # the server before answering. batch4, 5s later, finds nothing
    # listening -> connect fails outright.
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

        for i in range(BATCH):  # batch1, t=0s: conn1
            add_query("rcode0.test.", 0, i)
        for i in range(BATCH):  # batch2, t=2s: conn2
            add_query("rcode0.test.", 2, i)
        for i in range(BATCH):  # batch3, t=4s: conn3, kills the server
            add_query("terminate.test.", 4, i)
        for i in range(BATCH):  # batch4, t=9s: conn4 attempt, refused
            add_query("rcode0.test.", 9, i)

    config = TESTS_DIR / f"conn_reuse_idle0_{protocol}.toml"

    outdir = tmp_path / "out"
    with run_server(protocol, tmp_path) as (port, extra_port):
        run_replay_for(protocol, config, pcap_path, port, extra_port, outdir)

    sender = protocol.upper()
    merged_path = merge_stats(outdir, sender, tmp_path)
    stats_sum = get_stats_sum(read_records(merged_path))

    total = 4 * BATCH
    assert stats_sum["queries"] == total
    assert stats_sum["responses"] == 2 * BATCH  # batch1 + batch2 only
    assert stats_sum["timeouts"] == 2 * BATCH  # batch3 (unanswered) + batch4
    assert stats_sum["discarded"] == 0
    assert stats_sum["conn_info"]["type"] == CONN_TYPE[protocol]
    # 3 successful (batch1, batch2, batch3) + 1 failed attempt (batch4) --
    # conn_reuse_idle0_{tcp,dot}.toml set batch_size=128 so batch4's refused
    # connect is attempted (and counted) once, not retried once per default
    # 32-query dispatch chunk against a conn that goes CLOSED between chunks.
    assert stats_sum["conn_info"]["handshakes"] == 4
    assert stats_sum["conn_info"]["handshakes_failed"] == 1  # batch4
    assert stats_sum["conn_active"] == 0


def test_conn_recover(tmp_path):
    pcap_path = tmp_path / "queries.pcap"
    with open(pcap_path, "wb") as f:
        f.write(pcap_global_header())

        qid = 1

        def add_query(qname, ts_sec, ts_usec, client_id):
            nonlocal qid
            q = dns.message.make_query(qname, "A")
            q.id = qid
            write_packet_record(f, q.to_wire(), ts_sec, ts_usec, client_id)
            qid += 1

        for i in range(BATCH):  # t=0s: opens conn1
            add_query("rcode0.test.", 0, i, client_id=1)
        # t=2s: freezes the server for 3s, incl. its own accept().
        # idle_timeout_s=8 (config) survives this 2s gap since t=0.
        add_query("block3000.test.", 2, 0, client_id=1)
        for i in range(BATCH - 1):  # fillers sharing conn1
            add_query("rcode0.test.", 2, 1 + i, client_id=1)
        # t=2.3s, while frozen: fills backlog=0's one slot, succeeds at
        # kernel level regardless of freeze (connect() completes on
        # SYN-ACK, independent of the peer's accept()).
        for i in range(BATCH):
            add_query("rcode0.test.", 2, 300_000 + i, client_id=2)
        # t=2.6s: backlog slot already taken by the previous connect,
        # stalls; handshake_timeout_s=1 (config) gives up before freeze ends.
        for i in range(BATCH):
            add_query("rcode0.test.", 2, 600_000 + i, client_id=3)
        # t=10s (same source IP as above): reconnects, succeeds.
        for i in range(BATCH):
            add_query("rcode0.test.", 10, i, client_id=3)

    config = TESTS_DIR / "conn_reuse_block_backlog_tcp.toml"

    outdir = tmp_path / "out"
    with run_server("tcp", tmp_path) as (port, _):
        run_replay(config, pcap_path, port, outdir)

    merged_path = merge_stats(outdir, "TCP", tmp_path)
    stats_sum = get_stats_sum(read_records(merged_path))

    total = 5 * BATCH
    assert stats_sum["queries"] == total
    assert stats_sum["responses"] == 4 * BATCH  # everyone but client3's 1st attempt
    assert stats_sum["timeouts"] == BATCH  # client3's 1st-attempt queries, never sent
    assert stats_sum["discarded"] == 0
    assert stats_sum["conn_info"]["type"] == "tcp"
    assert stats_sum["conn_info"]["handshakes"] == 4
    assert stats_sum["conn_info"]["handshakes_failed"] == 1  # client3
    assert stats_sum["conn_active"] == 0


def test_conn_recover_dot(tmp_path):
    # Unlike plain TCP, a DoT connection isn't done at the TCP handshake --
    # dnssim tracks TCP+TLS as one combined handshake budget (single timer,
    # started at TCP connect, stopped only once ACTIVE), and TLS bytes can't
    # be exchanged until the frozen server wakes up. So a short
    # handshake_timeout_s (config) that reliably fails a backlog-refused
    # connection also fails the one occupying the backlog slot, since it
    # can't finish its TLS handshake before the freeze ends either -- both
    # client2 and client3's first attempts fail here, unlike test_conn_recover.
    pcap_path = tmp_path / "queries.pcap"
    with open(pcap_path, "wb") as f:
        f.write(pcap_global_header())

        qid = 1

        def add_query(qname, ts_sec, ts_usec, client_id):
            nonlocal qid
            q = dns.message.make_query(qname, "A")
            q.id = qid
            write_packet_record(f, q.to_wire(), ts_sec, ts_usec, client_id)
            qid += 1

        for i in range(BATCH):  # t=0s: opens conn1
            add_query("rcode0.test.", 0, i, client_id=1)
        # t=2s: freezes the server for 3s, incl. its own accept().
        # idle_timeout_s=8 (config) survives this 2s gap since t=0.
        add_query("block3000.test.", 2, 0, client_id=1)
        for i in range(BATCH - 1):  # fillers sharing conn1
            add_query("rcode0.test.", 2, 1 + i, client_id=1)
        # t=2.3s and t=2.6s, both while frozen: race for backlog=0's one
        # slot. Whichever occupies it still can't finish its TLS handshake
        # before handshake_timeout_s=1 (config) expires -- both fail.
        for i in range(BATCH):
            add_query("rcode0.test.", 2, 300_000 + i, client_id=2)
        for i in range(BATCH):
            add_query("rcode0.test.", 2, 600_000 + i, client_id=3)
        # t=10s: both reconnect (server long unfrozen by now) -- dnssim
        # requeues each client's earlier-failed queries onto this new
        # connection too, so every query ends up answered.
        for i in range(BATCH):
            add_query("rcode0.test.", 10, i, client_id=2)
        for i in range(BATCH):
            add_query("rcode0.test.", 10, 300_000 + i, client_id=3)

    config = TESTS_DIR / "conn_reuse_block_backlog_dot.toml"

    outdir = tmp_path / "out"
    with run_server("dot", tmp_path) as (port, dot_port):
        run_replay(config, pcap_path, port, outdir, dot_port=dot_port)

    merged_path = merge_stats(outdir, "DOT", tmp_path)
    stats_sum = get_stats_sum(read_records(merged_path))

    total = 6 * BATCH
    assert stats_sum["queries"] == total
    assert stats_sum["responses"] == total  # everyone eventually answered
    assert stats_sum["timeouts"] == 0
    assert stats_sum["discarded"] == 0
    assert stats_sum["conn_info"]["type"] == "tls_conn"
    assert stats_sum["conn_info"]["handshakes"] == 5
    assert stats_sum["conn_info"]["handshakes_failed"] == 2  # client2 + client3, 1st attempt
    assert stats_sum["conn_active"] == 0


@pytest.mark.parametrize("protocol", ["tcp", "dot", "doh"])
def test_conn_reuse_idle10(protocol, tmp_path):
    pcap_path = _build_pcap(tmp_path)
    config = TESTS_DIR / f"conn_reuse_idle10_{protocol}.toml"

    outdir = tmp_path / "out"
    with run_server(protocol, tmp_path) as (port, extra_port):
        run_replay_for(protocol, config, pcap_path, port, extra_port, outdir)

    sender = protocol.upper()
    merged_path = merge_stats(outdir, sender, tmp_path)
    stats_sum = get_stats_sum(read_records(merged_path))

    assert stats_sum["queries"] == NUM_QUERIES
    assert stats_sum["responses"] == NUM_QUERIES
    assert stats_sum["timeouts"] == 0
    assert stats_sum["discarded"] == 0
    assert stats_sum["conn_info"]["type"] == CONN_TYPE[protocol]
    # batch1's conn is still within its 10s idle window when batch2 arrives
    # 2s later -> reused, one handshake for the whole run.
    assert stats_sum["conn_info"]["handshakes"] == 1
    assert stats_sum["conn_info"]["handshakes_failed"] == 0
