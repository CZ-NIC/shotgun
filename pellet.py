#!/usr/bin/python3

import argparse
from collections import defaultdict
import dns
import dns.exception
import dns.message
from heapq import heappush, heappop
import ipaddress
import logging
import os
import random
import socket
import sys
import tempfile
import traceback
from typing import Dict, Iterator, List, Optional, Tuple, Union

import dpkt.pcap


IP = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
PcapIterator = Iterator[Tuple[float, dpkt.dpkt.Packet]]
PacketHeap = List[Tuple[float, dpkt.dpkt.Packet, PcapIterator]]

LINK_TYPES = {
    dpkt.pcap.DLT_EN10MB: dpkt.ethernet.Ethernet,
    dpkt.pcap.DLT_LINUX_SLL: dpkt.sll.SLL,
}


class NotEnoughInputDataError(RuntimeError):
    pass


def create_partial_files(
            pcap_in: dpkt.pcap.Reader,
            dest: str,
            clients: int,
            time_period: float
        ) -> int:
    """
    Each partial file contains simulated clients for the given
    time period. Multiple partial files will be created until the
    amount of clients needed is satisfied (or inpur PCAP runs out).
    """
    file_n = 1
    client_next = 1

    while True:
        partial_fname = '{0:04d}'.format(file_n)
        with open(os.path.join(dest, partial_fname), 'wb') as partial_fout:
            partial_pcap_out = dpkt.pcap.Writer(
                partial_fout, snaplen=66000, linktype=dpkt.pcap.DLT_RAW)
            time_offset = (file_n - 1) * time_period
            try:
                new_clients = process_time_chunk(
                    pcap_in, partial_pcap_out, client_next, clients, time_period, time_offset)
            except NotEnoughInputDataError:
                logging.error("No more available input data! Aborting prematurely...")
                break
            except RuntimeError as exc:
                logging.error('Unhandled exception: %s', exc)
                logging.debug(traceback.format_exc())
                break
            finally:
                partial_pcap_out.close()
            client_next += new_clients
            logging.info('chunk %04d: %d clients; total: %d / %d clients',
                         file_n, new_clients, client_next - 1, clients)
            file_n += 1
            if (client_next - 1) >= clients:
                break
    logging.info('generated %d clients in %d files', client_next - 1, file_n - 1)
    return file_n - 1


def join_partial_files(
            filename_out: str,
            tmpdir: str,
            nfiles: int,
        ) -> None:
    """
    The partial files are assumed to have the packets monotonically
    ordered by time. This function merges all input files such that
    the results is also monotonically ordered by time.
    """

    def pcap_yielder(
                filename_pcap: str
            ) -> PcapIterator:
        with open(filename_pcap, 'rb') as fin:
            pcap = dpkt.pcap.Reader(fin)
            for ts, pkt in pcap:
                yield ts, pkt

    def push(heap: PacketHeap, yielder: PcapIterator) -> None:
        try:
            val = next(yielder)
        except StopIteration:
            return
        else:
            heappush(heap, (val[0], val[1], yielder))

    logging.info('joining %d files...', nfiles)
    with open(filename_out, 'wb') as fout:
        try:
            pcap_out = dpkt.pcap.Writer(
                fout, snaplen=66000, linktype=dpkt.pcap.DLT_RAW)

            # use heap to sort packets from all partial pcaps
            heap = []  # type: PacketHeap
            for i in range(1, nfiles + 1):
                partial_fname = os.path.join(tmpdir, '{0:04d}'.format(i))
                yielder = pcap_yielder(partial_fname)
                push(heap, yielder)

            # write all packets to the output file
            while True:
                try:
                    item = heappop(heap)
                except IndexError:
                    break
                pcap_out.writepkt(item[1], ts=item[0])
                push(heap, item[2])
        finally:
            pcap_out.close()


def process_pcap(
            filename_in: str,
            filename_out: str,
            clients: int,
            time_period: float,
            ips: Optional[List[IP]] = None
        ) -> None:
    with open(filename_in, 'rb') as fin:
        pcap_in = dpkt.pcap.Reader(fin)
        if pcap_in.datalink() not in LINK_TYPES:
            logging.critical("Unsupported PCAP linktype")
            sys.exit(1)

        # read filter for 53/udp
        filter_ = create_filter(ips)
        logging.debug('using filter: "%s"', filter_)
        pcap_in.setfilter(filter_)

        with tempfile.TemporaryDirectory() as tmpdir:
            logging.debug('tmpdir: %s', tmpdir)

            nfiles = create_partial_files(pcap_in, tmpdir, clients, time_period)
            join_partial_files(filename_out, tmpdir, nfiles)
            logging.info('DONE: output PCAP created at %s', filename_out)


def get_client_address(client: int) -> bytes:
    assert client <= 0xffffffff
    template = "2001:db8:beef:feed::{0:04x}:{1:04x}"
    low = client & 0xffff
    high = (client & 0xffff0000) >> 16
    address = template.format(high, low)
    return socket.inet_pton(socket.AF_INET6, address)


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
    msgid_map = defaultdict(lambda: random.randint(0, 65535))  # type: Dict[bytes, int]
    dst_ip = socket.inet_pton(socket.AF_INET6, '::1')
    time_end = None

    parse = LINK_TYPES[pcap_in.datalink()]

    for ts, pkt in pcap_in:
        if time_end is None:  # TODO improve time handling to be consistent across chunks
            time_end = ts + time_period

        # check time period wasn't exceeded; return otherwise
        if ts > time_end:
            return client_n - client_start

        link = parse(pkt)

        ip = link.data
        if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
            continue

        udp = ip.data  # NOTE: ip packet musn't be fragmented
        if not isinstance(udp, dpkt.udp.UDP):
            continue

        payload = udp.data
        if not isinstance(payload, bytes):
            continue

        if len(payload) < 3:
            continue  # small garbage isn't supported
        if payload[2] & 0x80:
            continue  # QR=1 -> response

        try:  # ignore malformed queries
            dns.message.from_wire(payload)
        except dns.exception.FormError:
            continue

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

    raise NotEnoughInputDataError


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
