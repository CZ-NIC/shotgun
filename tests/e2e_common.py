"""
Shared plumbing for e2e tests that drive replay.py against ans.py:
build a PCAP from QNAMEs, run replay.py, merge per-thread JSON output.
"""
import contextlib
import glob
import json
import os
import pathlib
import random
import subprocess
import sys

from ans import run_in_subprocess
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


def replay_args(
    config, pcap_path, port, outdir, threads=4, dot_port=None, doh_port=None, doq_port=None
):
    args = [
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
    ]
    if dot_port is not None:
        args += ["--dot-port", str(dot_port)]
    if doh_port is not None:
        args += ["--doh-port", str(doh_port)]
    if doq_port is not None:
        args += ["--doq-port", str(doq_port)]
    return args


def run_replay_for(protocol, config, pcap_path, port, extra_port, outdir, threads=4):
    """
    run_replay(), routing extra_port (as yielded by run_server()) to
    --dot-port, --doh-port or --doq-port depending on protocol.
    """
    run_replay(
        config,
        pcap_path,
        port,
        outdir,
        threads,
        dot_port=extra_port if protocol == "dot" else None,
        doh_port=extra_port if protocol == "doh" else None,
        doq_port=extra_port if protocol == "doq" else None,
    )


def run_replay(
    config, pcap_path, port, outdir, threads=4, dot_port=None, doh_port=None, doq_port=None
):
    subprocess.run(
        replay_args(
            config, pcap_path, port, outdir, threads, dot_port, doh_port, doq_port
        ),
        cwd=REPO_ROOT,
        check=True,
    )


@contextlib.contextmanager
def run_server(protocol, tmp_path):
    """
    ans.run_in_subprocess(), yielding (port, extra_port) -- extra_port is
    None unless protocol is "dot", "doh" or "doq", in which case a
    TLS/DoH/DoQ listener with an ephemeral cert is also set up (see
    tls_cert.py).
    """
    if protocol == "dot":
        with run_in_subprocess(cert_dir=tmp_path) as (port, dot_port):
            yield port, dot_port
    elif protocol == "doh":
        with run_in_subprocess(cert_dir=tmp_path, doh=True) as (port, doh_port):
            yield port, doh_port
    elif protocol == "doq":
        with run_in_subprocess(cert_dir=tmp_path, doq=True) as (port, doq_port):
            yield port, doq_port
    else:
        with run_in_subprocess() as port:
            yield port, None


def merge_stats(outdir, sender, tmp_path, expected_threads=3):
    """
    Run tools/merge-data.py on the per-thread JSON, return the merged file's path.
    --summarize asserts stats_sum matches the stats_periodic records.
    """
    thread_jsons = sorted(glob.glob(str(outdir / "data" / sender / f"{sender}-*.json")))
    assert len(thread_jsons) == expected_threads

    merged_path = tmp_path / "merged.json"
    subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "tools" / "merge-data.py"),
            "--summarize",
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
