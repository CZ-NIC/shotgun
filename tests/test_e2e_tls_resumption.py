"""
e2e: TLS session resumption over DoT (dot_resumption.toml), checking
conn_info in the merged stats_sum.

Three query batches 2s apart, with idle_timeout_s=0 so each gets its own
connection: batch1 handshakes from scratch, batch2 and batch3 resume with
the ticket dnssim kept from the previous connection's close.

Batches, not single queries, for the reason conn_reuse's tests use them:
dnsjit's filter.timing:realtime() re-checks the pcap clock once per
128-packet batch, so packet position controls timing.
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
    run_replay_for,
    run_server,
)
from tcpdns2pcap import pcap_global_header, write_packet_record  # noqa: E402

BATCH = 128  # dnsjit's filter.timing:realtime() batch size
NUM_BATCHES = 3
NUM_QUERIES = NUM_BATCHES * BATCH


def _build_pcap(tmp_path) -> pathlib.Path:
    pcap_path = tmp_path / "queries.pcap"
    with open(pcap_path, "wb") as f:
        f.write(pcap_global_header())
        qid = 1
        for batch in range(NUM_BATCHES):
            for i in range(BATCH):
                query = dns.message.make_query("rcode0.test.", "A")
                query.id = qid
                write_packet_record(f, query.to_wire(), 2 * batch, i)
                qid += 1
    return pcap_path


@pytest.mark.parametrize("protocol", ["dot"])
def test_tls_resumption(protocol, tmp_path):
    pcap_path = _build_pcap(tmp_path)
    config = TESTS_DIR / f"{protocol}_resumption.toml"

    outdir = tmp_path / "out"
    with run_server(protocol, tmp_path) as (port, extra_port):
        run_replay_for(protocol, config, pcap_path, port, extra_port, outdir)

    merged_path = merge_stats(outdir, protocol.upper(), tmp_path)
    stats_sum = get_stats_sum(read_records(merged_path))

    assert stats_sum["queries"] == NUM_QUERIES
    assert stats_sum["responses"] == NUM_QUERIES
    assert stats_sum["timeouts"] == 0
    assert stats_sum["discarded"] == 0
    assert stats_sum["conn_info"]["type"] == "tls_conn"
    assert stats_sum["conn_info"]["handshakes"] == NUM_BATCHES
    assert stats_sum["conn_info"]["handshakes_failed"] == 0
    # Everything but batch1, which had no ticket to resume with yet.
    assert stats_sum["conn_info"]["resumption"]["established"] == NUM_BATCHES - 1
