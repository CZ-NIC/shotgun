#!/usr/bin/env python3
"""Generate a raw DNS-TCP-framed (RFC1035 4.2.2) stream of query messages.

Each message is preceded by a 2-byte big-endian length prefix, no other
framing. Used as input to tcpdns2pcap.py.
"""
import struct
import sys

import dns.message


def build_tcpdns_stream(qnames):
    """
    Build a raw DNS-TCP-framed (RFC1035 4.2.2) stream of A/IN queries, one
    per QNAME in `qnames`, with sequential message IDs starting at 1.
    """
    buf = bytearray()
    for i, qname in enumerate(qnames, start=1):
        q = dns.message.make_query(qname, "A", "IN")
        q.id = i
        wire = q.to_wire()
        buf += struct.pack("!H", len(wire))
        buf += wire
    return bytes(buf)


def main():
    outpath = sys.argv[1]
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 150

    if count <= 128:
        sys.exit(
            f"error: count={count} <= 128; dnsjit's filter.timing:realtime() only "
            "re-paces every rt_batch packets (default 128), so a pcap with <=128 "
            "packets replays with no real-time delay at all. Use count > 128."
        )

    with open(outpath, "wb") as f:
        f.write(build_tcpdns_stream(["t1."] * count))

    print(f"wrote {count} DNS query messages to {outpath}")

if __name__ == "__main__":
    main()
