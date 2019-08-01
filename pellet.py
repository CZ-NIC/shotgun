#!/usr/bin/python3

import argparse
import ipaddress
import logging
import sys
from typing import List, Optional, Union

import dpkt.pcap


IP = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


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
    for resolver in args.resolvers:
        try:
            ip = ipaddress.ip_address(resolver)
        except ValueError as exc:
            logging.error('--resolvers: %s', exc)
            sys.exit(1)
        else:
            ips.append(ip)

    process_pcap(args.pcap_in, args.output, args.clients, args.time, ips)


if __name__ == '__main__':
    main()
