"""per-RCODE response accounting."""

from collections import Counter

import json
import pathlib
import subprocess
import sys

import dns.rcode
import pytest

from ans import run_in_subprocess
from gen_tcpdns import build_tcpdns_stream

TESTS_DIR = pathlib.Path(__file__).parent
REPO_ROOT = TESTS_DIR.parent

# RCODE 12 exercises OTHER without EDNS.
STANDARD_RCODES = range(0, 11)
OTHER_RCODES = [12]
ALL_RCODES = list(STANDARD_RCODES) + OTHER_RCODES


def _rcode_bucket_name(rcode: int) -> str:
    return (
        dns.rcode.to_text(dns.rcode.Rcode(rcode))
        if rcode in STANDARD_RCODES
        else "OTHER"
    )


@pytest.mark.parametrize("protocol", ["udp", "tcp"])
def test_replay_rcodes(protocol, tmp_path):
    qnames = []
    expected_counts = Counter()
    for rcode in ALL_RCODES:
        bucket = _rcode_bucket_name(rcode)
        count = rcode + 1
        qnames += [f"rcode{rcode}.test."] * count
        expected_counts[bucket] += count

    total_queries = sum(expected_counts.values())

    tcpdns_path = tmp_path / "queries.tcpdns"
    tcpdns_path.write_bytes(build_tcpdns_stream(qnames))

    pcap_path = tmp_path / "queries.pcap"
    with open(tcpdns_path, "rb") as stdin_f, open(pcap_path, "wb") as stdout_f:
        subprocess.run(
            [sys.executable, str(TESTS_DIR / "tcpdns2pcap.py"), "1000"],
            stdin=stdin_f,
            stdout=stdout_f,
            check=True,
            cwd=TESTS_DIR,
        )

    outdir = tmp_path / "out"
    with run_in_subprocess() as port:
        subprocess.run(
            [
                sys.executable,
                "replay.py",
                "-c",
                protocol.lower(),
                "-r",
                str(pcap_path),
                "-s",
                "::1",
                "--dns-port",
                str(port),
                "-T",
                "2",
                "-O",
                str(outdir),
                "-f",
            ],
            cwd=REPO_ROOT,
            check=True,
        )

    sender = protocol.upper()
    json_path = outdir / "data" / sender / f"{sender}-01.json"
    records = [json.loads(line) for line in json_path.read_text().splitlines()]
    stats_sum = [r for r in records if r["type"] == "stats_sum"]
    assert len(stats_sum) == 1
    stats_sum = stats_sum[0]

    assert stats_sum["queries"] == total_queries
    assert stats_sum["responses"] == total_queries
    assert stats_sum["timeouts"] == 0
    assert stats_sum["discarded"] == 0
    assert stats_sum["response_rcodes"] == expected_counts
