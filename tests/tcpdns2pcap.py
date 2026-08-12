#!/usr/bin/env python3
"""
Convert a raw DNS-TCP-framed stream (2-byte BE length prefix + DNS wire
message, repeated) on stdin into a PCAP file containing IPv6/UDP/DNS
packets on stdout.

Writes a classic (non-nanosecond) PCAP file directly (LINKTYPE_RAW=101,
raw IP packets, no link-layer header).

Always uses ::1 and port 53 on both ends.

usage: tcpdns2pcap.py [spacing_us] < in.tcpdns > out.pcap
"""

import argparse
import struct
import sys

SRC_PORT = 53
DST_PORT = 53

IP6_LOOPBACK = b"\x00" * 15 + b"\x01"  # ::1

LINKTYPE_RAW = 101  # tcpdump.org registry value, portable (not OS-local DLT_RAW)


def build_packet(dns_wire: bytes, client_id: int = 1) -> bytes:
    udp_len = 2 + 2 + 2 + 2 + len(dns_wire)

    udp_hdr = struct.pack(
        "!HHHH", SRC_PORT, DST_PORT, udp_len, 0
    )  # checksum 0 = unused

    ip6_hdr = (
        bytes([0x60, 0x00, 0x00, 0x00])  # version=6, traffic class/flow label=0
        + struct.pack("!H", udp_len)  # payload length
        + bytes([17])  # next header = UDP
        + bytes([64])  # hop limit
        + client_id.to_bytes(16, "big")  # source address; ipsplit's client key
        + IP6_LOOPBACK  # dest address; ipsplit rewrites this regardless
    )

    return ip6_hdr + udp_hdr + dns_wire


def pcap_global_header() -> bytes:
    # All-big-endian incl. magic -> readers detect swapped magic and
    # byte-swap the rest (standard "swapped-endian" pcap dialect).
    return struct.pack(
        "!IHHIIII",
        0xA1B2C3D4,  # magic
        2,  # version_major
        4,  # version_minor
        0,  # thiszone
        0,  # sigfigs
        65535,  # snaplen
        LINKTYPE_RAW,  # network
    )


def read_next_message(stdin) -> bytes | None:
    """One length-prefixed tcpdns message, or None on clean EOF."""
    len_bytes = stdin.read(2)
    if not len_bytes:
        return None
    assert len(len_bytes) == 2, "truncated tcpdns stream: incomplete length prefix"
    (length,) = struct.unpack("!H", len_bytes)
    msg = stdin.read(length)
    assert len(msg) == length, "truncated tcpdns stream"
    return msg


def write_packet_record(
    stdout, dns_wire: bytes, ts_sec: int, ts_usec: int, client_id: int = 1
) -> None:
    packet = build_packet(dns_wire, client_id)
    rec = struct.pack("!IIII", ts_sec, ts_usec, len(packet), len(packet))
    stdout.write(rec)
    stdout.write(packet)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "spacing_us",
        nargs="?",
        type=int,
        default=300000,
        help="spacing between packets in us (default: 300 000)",
    )
    spacing_us = parser.parse_args().spacing_us

    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer

    stdout.write(pcap_global_header())

    ts_sec = 0
    ts_usec = 0
    count = 0
    while True:
        msg = read_next_message(stdin)
        if msg is None:
            break

        write_packet_record(stdout, msg, ts_sec, ts_usec)

        ts_usec += spacing_us
        while ts_usec >= 1000000:
            ts_usec -= 1000000
            ts_sec += 1
        count += 1

    print(f"wrote {count} packets to stdout", file=sys.stderr)


if __name__ == "__main__":
    main()
