"""
Shared plumbing for tests that drive replay.py against ans.py:
build a PCAP from QNAMEs, run replay.py, merge per-thread JSON output.
"""

from collections.abc import Mapping
import json
import os
import pathlib
import random
import subprocess
import sys

from gen_tcpdns import build_tcpdns_stream

TESTS_DIR = pathlib.Path(__file__).parent
REPO_ROOT = TESTS_DIR.parent

# dnsjit sends the first batch immediately, then paces each batch from its
# first packet's timestamp relative to the first PCAP packet. Packet position
# therefore matters; timestamps within a batch do not introduce delays.
PACING_BATCH = 128


def seeded_rng() -> random.Random:
    """
    A random.Random seeded from the SEED env var, or a fresh random seed
    (printed, so a failure can be rerun with SEED=<seed> pytest ... -s).
    """
    seed = int(os.environ.get("SEED", random.randrange(2**32)))
    print(f"SEED={seed}")
    return random.Random(seed)


def build_pcap(qnames, tmp_path, spacing_us=1000) -> pathlib.Path:
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


def run_replay(config, pcap_path, port, outdir, threads=4) -> None:
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


def merge_stats(outdir, sender, tmp_path, expected_jsons=3) -> pathlib.Path:
    """Run tools/merge-data.py on the per-thread JSON, return the merged file's path."""
    thread_jsons = sorted(outdir.glob(f"data/{sender}/{sender}-*.json"))
    assert len(thread_jsons) == expected_jsons

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


def read_records(merged_path) -> list[dict]:
    return [json.loads(line) for line in merged_path.read_text().splitlines()]


def get_stats_sum(records) -> dict:
    matches = [r for r in records if r["type"] == "stats_sum"]
    assert len(matches) == 1
    return matches[0]


def get_stats_periodic(records) -> list[dict]:
    return [r for r in records if r["type"] == "stats_periodic"]


def select_expected_fields(actual, expected) -> dict:
    """Select expected mapping keys recursively, preserving complete leaf values."""
    expected_keys = set(expected)
    got_keys = expected_keys.intersection(actual)
    assert got_keys == expected_keys

    return {
        key: (
            select_expected_fields(actual[key], value)
            if isinstance(value, Mapping)
            else actual[key]
        )
        for key, value in expected.items()
    }
