"""per-RCODE accounting, including TC=1 without TCP fallback."""

from collections import Counter

import itertools

import dns.rcode
import pytest

from ans import run_in_subprocess
from common import (
    build_pcap,
    get_stats_sum,
    merge_stats,
    read_records,
    run_replay,
    seeded_rng,
)

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
    rng = seeded_rng()

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

    pcap_path = build_pcap(qnames, tmp_path)

    # -T4 creates 3 sender threads; 1 source IP sends all queries to one thread.
    outdir = tmp_path / "out"
    with run_in_subprocess() as port:
        run_replay(protocol.lower(), pcap_path, port, outdir)

    sender = protocol.upper()
    merged_path = merge_stats(outdir, sender, tmp_path)
    records = read_records(merged_path)
    stats_sum = get_stats_sum(records)

    assert stats_sum["queries"] == total_queries
    assert stats_sum["responses"] == total_queries - expected_timeouts
    assert stats_sum["timeouts"] == expected_timeouts
    assert stats_sum["discarded"] == 0
    assert stats_sum["response_rcodes"] == expected_counts
