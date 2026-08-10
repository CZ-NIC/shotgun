#!/usr/bin/env python3
"""Generate a raw DNS-TCP-framed (RFC1035 4.2.2) stream of query messages.

Each message is preceded by a 2-byte big-endian length prefix, no other
framing. Used as input to tcpdns2pcap.lua.
"""
import struct
import sys

import dns.message

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
        for i in range(1, count + 1):
            q = dns.message.make_query("t1.", "A", "IN")
            q.id = i
            wire = q.to_wire()
            f.write(struct.pack("!H", len(wire)))
            f.write(wire)

    print(f"wrote {count} DNS query messages to {outpath}")

if __name__ == "__main__":
    main()
