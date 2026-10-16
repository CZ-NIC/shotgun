"""SIGINT preserves flushed periods without producing a summary."""

import json
import os
import pathlib
import signal
import subprocess
import sys
import time

import dns.message
import pytest

from ans import run_in_subprocess
from common import PACING_BATCH, REPO_ROOT, read_records
from testconfigs import make_config
from tcpdns2pcap import pcap_global_header, write_packet_record

QPS = PACING_BATCH
DURATION_S = 5
# sigint_{udp,tcp}.toml: timeout_s=1, so period1 (ends 1s) is write-eligible
# at 2s and period2 (ends 2s) at 3s; period3 (ends 3s) needs 4s. 3.5s gives
# ~0.5s margin past period2's threshold and before period3's.
SIGINT_AFTER_S = 3.5


def _build_pcap(tmp_path) -> pathlib.Path:
    pcap_path = tmp_path / "queries.pcap"
    with open(pcap_path, "wb") as f:
        f.write(pcap_global_header())
        qid = 1
        for sec in range(DURATION_S):
            for i in range(QPS):
                q = dns.message.make_query("rcode0.test.", "A")
                q.id = qid
                write_packet_record(f, q.to_wire(), sec, i * (1_000_000 // QPS))
                qid += 1
    return pcap_path


def _run_replay_and_interrupt(config, pcap_path, port, outdir):
    # start_new_session so SIGINT hits replay.py + dnsjit child, like a real
    # terminal Ctrl+C would (both are in the foreground process group).
    proc = subprocess.Popen(  # pylint: disable=consider-using-with
        [
            sys.executable,
            "replay.py",
            "-c",
            str(config),
            "-r",
            str(pcap_path),
            "-s",
            "::1",
            "--dns-port",
            str(port),
            "-T",
            "4",
            "-O",
            str(outdir),
            "-f",
        ],
        cwd=REPO_ROOT,
        start_new_session=True,
    )
    time.sleep(SIGINT_AFTER_S)
    os.killpg(os.getpgid(proc.pid), signal.SIGINT)
    proc.wait(timeout=10)
    return proc.returncode


@pytest.mark.parametrize("protocol", ["udp", "tcp"])
def test_sigint_partial_results(protocol, tmp_path):
    pcap_path = _build_pcap(tmp_path)
    config, sender = make_config(tmp_path, "sigint", protocol)
    outdir = tmp_path / "out"

    with run_in_subprocess() as port:
        returncode = _run_replay_and_interrupt(config, pcap_path, port, outdir)

    assert returncode != 0  # killed, not a clean exit

    thread_jsons = sorted((outdir / "data" / sender).glob(f"{sender}-*.json"))
    assert thread_jsons

    for p in thread_jsons:
        for line in p.read_text().splitlines():
            json.loads(line)

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
    assert len(periodic) == 2  # period1, period2 write-eligible; period3 not yet
    assert summed == []

    period1, period2 = periodic
    # dnsjit's realtime filter sends the first pacing batch instantly
    # (no pacing yet), so period1 absorbs 2 batches before real-time
    # throttling settles in; period2 sees the steady-state QPS.
    for period, expected in ((period1, 2 * QPS), (period2, QPS)):
        assert period["queries"] == expected
        assert period["responses"] == expected
        assert period["timeouts"] == 0
        assert period["discarded"] == 0
        assert period["response_rcodes"] == {"NOERROR": expected}
