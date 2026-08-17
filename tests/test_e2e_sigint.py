"""
e2e: SIGINT mid-run must not corrupt stats already flushed to disk.

A period is only written once its own end plus timeout_s has passed
(dnssim.c _on_stats_timer_tick), so any request sent in it has had a chance
to time out first. dnssim fflushes each such record immediately, so already
-written periods survive an abrupt kill; the still-open period does not.
stats_sum is only written on clean shutdown (output_dnssim_close_file), so
it's expected to be missing.
"""
import json
import os
import pathlib
import signal
import subprocess
import sys
import time

import dns.message
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from e2e_common import (  # noqa: E402
    REPO_ROOT,
    TESTS_DIR,
    read_records,
    replay_args,
    run_server,
)
from tcpdns2pcap import pcap_global_header, write_packet_record  # noqa: E402

QPS = 128
DURATION_S = 5
EXPECTED_PERIODS = 2
# Ceiling for waiting until EXPECTED_PERIODS periods have been flushed, not
# a target: sigint_*.toml sets timeout_s=1, so period1 (ends 1s) becomes
# write-eligible at 2s and period2 at 3s (dnssim.c _on_stats_timer_tick),
# but the run's clock starts whenever dnsjit finishes setting up. Waiting
# for the records themselves rather than for a fixed moment keeps the
# interrupt inside period3's window however long that takes. Generous
# because it costs nothing when the run is healthy, and a machine loaded
# enough to need it has already made the wait unpredictable.
SIGINT_TIMEOUT_S = 30


# Each second's queries are packed into a sub-millisecond burst rather than
# spread across the second, which makes a burst indivisible: dnsjit hands it
# over in one go and dnssim dequeues it in one chunk (batch_size >= QPS, see
# sigint_*.toml), and the stats timer only fires between dequeues. A period
# therefore holds whole bursts.
#
# Which period a burst lands in is not controllable from here. dnsjit's
# filter.timing:realtime() only consults the clock every 128 packets and
# sleeps until that packet's timestamp, so the packets following an anchor
# are handed over with no pacing at all -- a burst can be released up to a
# second early. Spread-out queries made this worse, splitting a second's
# queries across two periods in batch_size chunks (periods of 160 or 192);
# with bursts, a period holds one or two whole bursts.
QUERY_BURST_START_US = 100_000
QUERY_BURST_SPACING_US = 1


def _build_pcap(tmp_path) -> pathlib.Path:
    pcap_path = tmp_path / "queries.pcap"
    with open(pcap_path, "wb") as f:
        f.write(pcap_global_header())
        qid = 1
        for sec in range(DURATION_S):
            for i in range(QPS):
                q = dns.message.make_query("rcode0.test.", "A")
                q.id = qid
                usec = QUERY_BURST_START_US + i * QUERY_BURST_SPACING_US
                write_packet_record(f, q.to_wire(), sec, usec)
                qid += 1
    return pcap_path


def _thread_jsons(outdir, sender):
    data_dir = outdir / "data" / sender
    if not data_dir.is_dir():
        return []
    return sorted(data_dir.glob(f"{sender}-*.json"))


def _wait_for_flushed_periods(outdir, sender, threads=3):
    """
    Block until every thread has flushed EXPECTED_PERIODS periods, so the
    interrupt lands after those records are on disk and before the next one
    is due. Returns as soon as the condition holds, leaving most of a period
    (the stats interval, 1s) before another record could appear.
    """
    deadline = time.monotonic() + SIGINT_TIMEOUT_S
    while time.monotonic() < deadline:
        paths = _thread_jsons(outdir, sender)
        if len(paths) == threads:
            flushed = [
                sum(
                    1
                    for line in path.read_text().splitlines()
                    if json.loads(line)["type"] == "stats_periodic"
                )
                for path in paths
            ]
            if all(count >= EXPECTED_PERIODS for count in flushed):
                return
        time.sleep(0.05)
    raise TimeoutError(f"{sender}: {EXPECTED_PERIODS} periods were never flushed")


def _run_replay_and_interrupt(
    config, pcap_path, port, outdir, sender, dot_port=None, doh_port=None, doq_port=None
):
    # start_new_session so SIGINT hits replay.py + dnsjit child, like a real
    # terminal Ctrl+C would (both are in the foreground process group).
    proc = subprocess.Popen(
        replay_args(
            config,
            pcap_path,
            port,
            outdir,
            dot_port=dot_port,
            doh_port=doh_port,
            doq_port=doq_port,
        ),
        cwd=REPO_ROOT,
        start_new_session=True,
    )
    try:
        _wait_for_flushed_periods(outdir, sender)
    finally:
        # Even when the wait gives up: start_new_session put the run in its
        # own process group, so nothing else will reap it, and a replay left
        # running competes with whatever runs next.
        os.killpg(os.getpgid(proc.pid), signal.SIGINT)
        proc.wait(timeout=10)
    return proc.returncode


@pytest.mark.parametrize("protocol", ["udp", "tcp", "dot", "doh", "doq"])
def test_sigint_partial_results(protocol, tmp_path):
    pcap_path = _build_pcap(tmp_path)
    config = TESTS_DIR / f"sigint_{protocol}.toml"
    outdir = tmp_path / "out"
    sender = protocol.upper()

    with run_server(protocol, tmp_path) as (port, extra_port):
        returncode = _run_replay_and_interrupt(
            config,
            pcap_path,
            port,
            outdir,
            sender,
            dot_port=extra_port if protocol == "dot" else None,
            doh_port=extra_port if protocol == "doh" else None,
            doq_port=extra_port if protocol == "doq" else None,
        )

    assert returncode != 0  # killed, not a clean exit

    thread_jsons = _thread_jsons(outdir, sender)
    assert thread_jsons

    for p in thread_jsons:
        for line in p.read_text().splitlines():
            json.loads(line)  # every flushed line is complete, valid JSON

    merged_path = tmp_path / "merged.json"
    subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "tools" / "merge-data.py"),
            *(str(p) for p in thread_jsons),
            "-o",
            str(merged_path),
        ],
        check=True,
    )

    records = read_records(merged_path)
    periodic = [r for r in records if r["type"] == "stats_periodic"]
    summed = [r for r in records if r["type"] == "stats_sum"]
    assert len(periodic) == EXPECTED_PERIODS  # what the interrupt waited for
    assert summed == []  # close_file() never reached on abrupt kill

    # Whole bursts only, and every query in them accounted for. The exact
    # count per period is deliberately not asserted: which period a burst
    # lands in depends on dnsjit's 128-packet pacing granularity (see
    # QUERY_BURST_START_US above), so a period holds one or two bursts. What
    # a flushed record must never be is internally inconsistent - a partial
    # burst, or queries whose responses went missing.
    assert sum(p["queries"] for p in periodic) >= QPS
    for period in periodic:
        assert period["queries"] % QPS == 0
        assert period["responses"] == period["queries"]
        assert period["timeouts"] == 0
        assert period["discarded"] == 0
        expected_rcodes = {"NOERROR": period["queries"]} if period["queries"] else {}
        assert period["response_rcodes"] == expected_rcodes
