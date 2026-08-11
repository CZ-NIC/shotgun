"""
Shared plumbing for e2e tests that drive replay.py against ans.py:
build a PCAP from QNAMEs, run replay.py, merge per-thread JSON output.
"""
import glob
import json
import os
import pathlib
import random
import subprocess
import sys

from gen_tcpdns import build_tcpdns_stream

TESTS_DIR = pathlib.Path(__file__).parent
REPO_ROOT = TESTS_DIR.parent


def seeded_rng() -> random.Random:
    """
    A random.Random seeded from the SEED env var, or a fresh random seed
    (printed, so a failure can be rerun with SEED=<seed> pytest ... -s).
    """
    seed = int(os.environ.get("SEED", random.randrange(2**32)))
    print(f"seed={seed}")
    return random.Random(seed)


def build_pcap(qnames, tmp_path, spacing_us=1000):
    tcpdns_path = tmp_path / "queries.tcpdns"
    tcpdns_path.write_bytes(build_tcpdns_stream(qnames))

    pcap_path = tmp_path / "queries.pcap"
    with open(tcpdns_path, "rb") as stdin_f, open(pcap_path, "wb") as stdout_f:
        subprocess.run(
            [sys.executable, str(TESTS_DIR / "tcpdns2pcap.py"), str(spacing_us)],
            stdin=stdin_f,
            stdout=stdout_f,
            check=True,
            cwd=TESTS_DIR,
        )
    return pcap_path


def run_replay(config, pcap_path, port, outdir, threads=4):
    subprocess.run(
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
            str(threads),
            "-O",
            str(outdir),
            "-f",
        ],
        cwd=REPO_ROOT,
        check=True,
    )


def merge_stats(outdir, sender, tmp_path, expected_threads=3):
    """Run tools/merge-data.py on the per-thread JSON, return the merged file's path."""
    thread_jsons = sorted(glob.glob(str(outdir / "data" / sender / f"{sender}-*.json")))
    assert len(thread_jsons) == expected_threads

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
    return merged_path


def read_records(merged_path):
    return [json.loads(line) for line in merged_path.read_text().splitlines()]


def get_stats_sum(records):
    matches = [r for r in records if r["type"] == "stats_sum"]
    assert len(matches) == 1
    return matches[0]


def get_stats_periodic(records):
    return [r for r in records if r["type"] == "stats_periodic"]
