"""per-RCODE accounting, including TC=1 without TCP fallback."""

from collections import Counter

import glob
import itertools
import json
import os
import pathlib
import random
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

# Exclude cutshort: a malformed TCP response can close the connection
# and disrupt unrelated queries.
IGNORED_RESPONSE_MODIFIERS = [
    "idmismatch",
    "opcodemismatch",
    "qtypemismatch",
    "qcasemismatch",
    "qdcountmismatch",
    "qr0",
]


def _rcode_bucket_name(rcode: int) -> str:
    return (
        dns.rcode.to_text(dns.rcode.Rcode(rcode))
        if rcode in STANDARD_RCODES
        else "OTHER"
    )


@pytest.mark.parametrize("protocol", ["udp", "tcp"])
def test_replay_rcodes(protocol, tmp_path):
    seed = int(os.environ.get("SEED", random.randrange(2**32)))
    print(f"seed={seed}")  # rerun a failure with SEED=<seed> pytest ... -s
    rng = random.Random(seed)

    modifiers = IGNORED_RESPONSE_MODIFIERS.copy()
    rng.shuffle(modifiers)
    modifier_cycle = itertools.cycle(modifiers)

    qnames = []
    expected_counts = Counter()
    expected_timeouts = 0
    used_modifiers = set()
    for rcode in ALL_RCODES:
        bucket = _rcode_bucket_name(rcode)
        count = rcode + 1
        for suffix in ("", "-tc1"):
            qnames += [f"rcode{rcode}{suffix}.test."] * count
            expected_counts[bucket] += count
        modifier = next(modifier_cycle)
        used_modifiers.add(modifier)
        qnames.append(f"rcode{rcode}-{modifier}.test.")
        expected_timeouts += 1  # one ignored-response query per RCODE
    assert used_modifiers == set(IGNORED_RESPONSE_MODIFIERS)

    total_queries = sum(expected_counts.values()) + expected_timeouts

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

    # -T4 creates 3 sender threads; 1 source IP sends all queries to one thread.
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
                "4",
                "-O",
                str(outdir),
                "-f",
            ],
            cwd=REPO_ROOT,
            check=True,
        )

    sender = protocol.upper()
    thread_jsons = sorted(glob.glob(str(outdir / "data" / sender / f"{sender}-*.json")))
    assert len(thread_jsons) == 3  # -T4 = 1 main + 3 sender threads (1 sender)

    merged_path = tmp_path / "merged.json"
    subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "tools" / "merge-data.py"),
            *thread_jsons,
            "-o",
            str(merged_path),
        ],
        check=True,
    )

    records = [json.loads(line) for line in merged_path.read_text().splitlines()]
    stats_sum = [r for r in records if r["type"] == "stats_sum"]
    assert len(stats_sum) == 1
    stats_sum = stats_sum[0]

    assert stats_sum["queries"] == total_queries
    assert stats_sum["responses"] == total_queries - expected_timeouts
    assert stats_sum["timeouts"] == expected_timeouts
    assert stats_sum["discarded"] == 0
    assert stats_sum["response_rcodes"] == expected_counts
