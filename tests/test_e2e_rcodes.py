"""
e2e: replay.py over UDP/TCP vs ans.py, all RCODEs 0-10 plus non-standard 12,
each also with TC=1. RCODE N gets N+1 queries per TC variant (so 2*(N+1)
total); checks per-RCODE counts in replay.py's JSON. TC=1 doesn't change the
expected RCODE bucket: UDP transport has no TCP fallback, so a truncated
response is still counted by its own RCODE, not retried.

One ignored-response query is also inserted after each RCODE's block, cycling
IGNORED_RESPONSE_MODIFIERS in random order (all get exercised). Each makes
dnssim reject the response without recording an answer -> query times out.

"cutshort" excluded: over TCP it makes dnssim close the whole connection
(connection.c:671), killing other pending queries too -- caused flaky counts.
"""
import itertools
import os
import pathlib
import random
import sys

import dns.rcode
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from ans import run_in_subprocess  # noqa: E402
from e2e_common import build_pcap, merge_stats_sum, run_replay  # noqa: E402

# 0-10: named in dnssim's rcode table. 11-15: unassigned 4-bit values, no
# dedicated name -> counted as "OTHER" (replay/dnssim/src/output/dnssim.c).
STANDARD_RCODES = range(0, 11)
OTHER_RCODES = [12]
ALL_RCODES = list(STANDARD_RCODES) + OTHER_RCODES

# ans.py instructions -> ignored response -> timeout (see docstring re: cutshort)
IGNORED_RESPONSE_MODIFIERS = [
    "idmismatch",
    "opcodemismatch",
    "qtypemismatch",
    "qcasemismatch",
    "qdcountmismatch",
    "qr0",
]


def _rcode_bucket_name(rcode: int) -> str:
    return dns.rcode.to_text(rcode) if rcode in STANDARD_RCODES else "OTHER"


@pytest.mark.parametrize("protocol", ["udp", "tcp"])
def test_replay_rcodes(protocol, tmp_path):
    seed = int(os.environ.get("SEED", random.randrange(2**32)))
    print(f"seed={seed}")  # rerun a failure with SEED=<seed> pytest ... -s
    rng = random.Random(seed)

    modifiers = IGNORED_RESPONSE_MODIFIERS.copy()
    rng.shuffle(modifiers)
    modifier_cycle = itertools.cycle(modifiers)

    qnames = []
    used_modifiers = set()
    for rcode in ALL_RCODES:
        for suffix in ("", "-tc1"):
            qnames += [f"rcode{rcode}{suffix}.test."] * (rcode + 1)
        modifier = next(modifier_cycle)
        used_modifiers.add(modifier)
        qnames.append(f"rcode{rcode}-{modifier}.test.")
    assert used_modifiers == set(IGNORED_RESPONSE_MODIFIERS)

    expected_counts: dict[str, int] = {}
    for rcode in ALL_RCODES:
        bucket = _rcode_bucket_name(rcode)
        expected_counts[bucket] = expected_counts.get(bucket, 0) + 2 * (rcode + 1)
    expected_timeouts = len(ALL_RCODES)  # one ignored-response query per RCODE
    total_queries = sum(expected_counts.values()) + expected_timeouts

    pcap_path = build_pcap(qnames, tmp_path)

    outdir = tmp_path / "out"
    with run_in_subprocess() as port:
        run_replay(protocol.lower(), pcap_path, port, outdir)

    sender = protocol.upper()
    stats_sum = merge_stats_sum(outdir, sender, tmp_path)

    assert stats_sum["queries"] == total_queries
    assert stats_sum["responses"] == total_queries - expected_timeouts
    assert stats_sum["timeouts"] == expected_timeouts
    assert stats_sum["discarded"] == 0
    assert stats_sum["response_rcodes"] == expected_counts
