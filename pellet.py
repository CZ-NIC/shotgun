#!/usr/bin/python3

import argparse
from collections import defaultdict
from heapq import heappush, heappop
import ipaddress
import logging
import os
import socket
import sys
import tempfile
import traceback
from typing import Dict, Iterator, List, Optional, Tuple, Union

import dpkt.pcap


IP = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


def pcap_yielder(filename_pcap: str) -> Iterator[Tuple[float, dpkt.dpkt.Packet]]:
    with open(filename_pcap, 'rb') as fin:
        pcap = dpkt.pcap.Reader(fin)
        for ts, pkt in pcap:
            yield ts, pkt


def process_pcap(
            filename_in: str,
            filename_out: str,
            clients: int,
            time: float,
            ips: Optional[List[IP]] = None
        ) -> None:
    with open(filename_in, 'rb') as fin:
        pcap_in = dpkt.pcap.Reader(fin)

        filter_ = create_filter(ips)
        logging.debug('using filter: "%s"', filter_)
        pcap_in.setfilter(filter_)

        with tempfile.TemporaryDirectory() as tmpdir:
            logging.info('tmpdir: %s', tmpdir)
            file_n = 1
            client_next = 1

            while True:
                partial_fname = '{0:04d}'.format(file_n)
                with open(os.path.join(tmpdir, partial_fname), 'wb') as partial_fout:
                    partial_pcap_out = dpkt.pcap.Writer(
                        partial_fout, snaplen=66000, linktype=dpkt.pcap.DLT_RAW)
                    time_offset = (file_n - 1) * time
                    try:
                        new_clients = process_time_chunk(
                            pcap_in, partial_pcap_out, client_next, clients, time, time_offset)
                    finally:
                        partial_pcap_out.close()
                    client_next += new_clients
                    logging.info('chunk %04d: %d clients; total: %d / %d clients',
                                 file_n, new_clients, client_next - 1, clients)
                    file_n += 1
                    if (client_next - 1) >= clients:
                        break

            # join file
            logging.info('joining %d files...', file_n - 1)
            with open(filename_out, 'wb') as fout:
                pcap_out = dpkt.pcap.Writer(
                    fout, snaplen=66000, linktype=dpkt.pcap.DLT_RAW)

                def push(heap, yielder):
                    try:
                        val = next(yielder)
                    except StopIteration:
                        return
                    else:
                        heappush(heap, (val[0], val[1], yielder))

                heap = []  # type: List[Tuple[float, dpkt.packet.Packet, Iterator]]
                for i in range(1, file_n):
                    partial_fname = os.path.join(tmpdir, '{0:04d}'.format(i))
                    yielder = pcap_yielder(partial_fname)
                    push(heap, yielder)

                while True:
                    try:
                        item = heappop(heap)
                    except IndexError:
                        break
                    pcap_out.writepkt(item[1], ts=item[0])
                    push(heap, item[2])

                pcap_out.close()


def get_client_address(client: int) -> bytes:
    assert client <= 0xffffffff
    template = "2001:db8:beef:feed::{0:04x}:{1:04x}"
    low = client & 0xffff
    high = (client & 0xffff0000) >> 16
    address = template.format(high, low)
    return socket.inet_pton(socket.AF_INET6, address)


# def get_client_address(client: int) -> bytes:
#     assert client <= 0x00fffffff
#     oct1 = 10
#     oct2 = (client & 0xff0000) >> 16
#     oct3 = (client & 0xff00) >> 8
#     oct4 = client & 0xff
#     return bytes([oct1, oct2, oct3, oct4])


def process_time_chunk(
            pcap_in: dpkt.pcap.Reader,
            pcap_out: dpkt.pcap.Writer,
            client_start: int,
            max_clients: int,
            time_period: float,
            time_offset: float,
        ) -> int:
    client_n = client_start
    client_map = {}  # type: Dict[bytes, bytes]
    msgid_map = defaultdict(int)  # type: Dict[bytes, int]
    dst_ip = socket.inet_pton(socket.AF_INET6, '::1')
    time_end = None

    for ts, pkt in pcap_in:
        if time_end is None:  # TODO improve time handling to be consistent across chunks
            time_end = ts - time_offset + time_period

        eth = dpkt.ethernet.Ethernet(pkt)
        ip = eth.data
        # TODO ip more fragments?
        # TODO check ipv6 compatiblity
        udp = ip.data
        payload = udp.data

        if len(payload) < 3:
            continue  # small garbage isn't supported
        if payload[2] & 0x80:
            continue  # QR=1 -> response

        # try:
        #     dns = dpkt.dns.DNS(udp.data)  # TODO add support for garbage?
        # except (dpkt.dpkt.UnpackError, UnicodeDecodeError) as exc:
        #     # TODO must be fixed - NSEC, RRSIG, DS ...
        #     logging.warning('dropping packet due to parse error: %s', exc)
        #     continue
        # if dns.qr != dpkt.dns.DNS_Q:
        #     continue
        # if dns.opcode != dpkt.dns.DNS_QUERY:
        #     continue

        # do mapping from original ip to client; new client otherwise
        try:
            client_ip = client_map[ip.src]
        except KeyError:
            if client_n > max_clients:
                continue  # no more clients needed

            client_ip = get_client_address(client_n)
            client_map[ip.src] = client_ip
            client_n += 1

        # adjust time for pcap
        ts -= time_offset

        # set msgid to next sequential id
        msgid = msgid_map[client_ip]
        msgid_map[client_ip] += 1
        payload = bytearray(payload)
        payload[0] = (msgid & 0xff00) >> 8
        payload[1] = msgid & 0xff
        payload = bytes(payload)

        # prepare the packet
        udp_out = dpkt.udp.UDP(data=payload, dport=53)
        udp_out.ulen = len(udp_out)
        ip_out = dpkt.ip6.IP6()
        ip_out.src = client_ip
        ip_out.dst = dst_ip
        ip_out.hlim = 64
        ip_out.nxt = dpkt.ip.IP_PROTO_UDP
        ip_out.data = udp_out
        ip_out.plen = udp_out.ulen

        # write dns message to pcap
        pcap_out.writepkt(ip_out, ts=ts)

        # check time period wasn't exceeded; break otherwise
        if ts > time_end:
            logging.info('%f %f', ts, time_period)
            return client_n - client_start

    # TODO: discard chunk, keep the rest, issue warning
    raise NotImplementedError


def create_filter(ips: Optional[List[IP]] = None) -> str:
    cap_filter = 'udp dst port 53'
    if ips:
        hosts = ['host {}'.format(ip) for ip in ips]
        cap_filter += ' and ({})'.format(' or '.join(hosts))
    return cap_filter


def main():
    parser = argparse.ArgumentParser(
        description='prepare PCAP with pseudoclients for shotgun')
    parser.add_argument('pcap_in', type=str, help='input PCAP file to process')
    parser.add_argument(
        '-c', '--clients', type=int, default=10000,
        help='number of clients to prepare')
    parser.add_argument(
        '-t', '--time', type=float, default=300,
        help='how many seconds to simulate')
    parser.add_argument(
        '-o', '--output', type=str, default='pellets.pcap',
        help='output PCAP file with pseudoclients')
    parser.add_argument(
        '-r', '--resolvers', type=str, nargs='*',
        help='only use data flowing to specified addresses (IP/IPv6)')

    args = parser.parse_args()

    logging.basicConfig(
        format='%(asctime)s %(levelname)8s  %(message)s', level=logging.DEBUG)

    ips = []
    if args.resolvers:
        for resolver in args.resolvers:
            try:
                ip = ipaddress.ip_address(resolver)
            except ValueError as exc:
                logging.critical('--resolvers: %s', exc)
                sys.exit(1)
            else:
                ips.append(ip)

    try:
        process_pcap(args.pcap_in, args.output, args.clients, args.time, ips)
    except FileNotFoundError as exc:
        logging.critical('%s', exc)
        sys.exit(1)
    except Exception as exc:
        logging.critical('uncaught exception: %s', exc)
        logging.debug(traceback.format_exc())
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
