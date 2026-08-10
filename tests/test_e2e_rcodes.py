"""
Minimal e2e test: replay.py over UDP against ans.py (QnameInstructionHandler),
exercising every standard RCODE and checking that the number of queries per
RCODE reported in replay.py's JSON output matches what was sent.

For RCODE N, N+1 queries encoding "rcodeN" are sent (so RCODE=0 gets 1 query,
RCODE=1 gets 2, ..., RCODE=10 gets 11).
"""
import json
import pathlib
import subprocess
import sys

import dns.rcode

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from ans import run_in_subprocess  # noqa: E402
from gen_tcpdns import build_tcpdns_stream  # noqa: E402

TESTS_DIR = pathlib.Path(__file__).parent
REPO_ROOT = TESTS_DIR.parent

# RCODEs 0-10 are the only ones with well-known names on both ends (ans.py's
# QnameInstructionHandler and dnssim's hardcoded rcode_names table); higher
# values require EDNS extended-RCODE encoding and are out of scope here.
STANDARD_RCODES = range(0, 11)


def test_replay_udp_rcodes(tmp_path):
    qnames = [
        f"rcode{rcode}.test."
        for rcode in STANDARD_RCODES
        for _ in range(rcode + 1)
    ]
    expected_counts = {
        dns.rcode.to_text(rcode): rcode + 1 for rcode in STANDARD_RCODES
    }
    total_queries = sum(expected_counts.values())

    tcpdns_path = tmp_path / "queries.tcpdns"
    tcpdns_path.write_bytes(build_tcpdns_stream(qnames))

    pcap_path = tmp_path / "queries.pcap"
    with open(tcpdns_path, "rb") as stdin_f, open(pcap_path, "wb") as stdout_f:
        subprocess.run(
            ["dnsjit", str(TESTS_DIR / "tcpdns2pcap.lua"), "1000"],
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
                "udp",
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

    json_path = outdir / "data" / "UDP" / "UDP-01.json"
    records = [json.loads(line) for line in json_path.read_text().splitlines()]
    stats_sum = [r for r in records if r["type"] == "stats_sum"]
    assert len(stats_sum) == 1
    stats_sum = stats_sum[0]

    assert stats_sum["queries"] == total_queries
    assert stats_sum["responses"] == total_queries
    assert stats_sum["timeouts"] == 0
    assert stats_sum["discarded"] == 0
    assert stats_sum["response_rcodes"] == expected_counts
