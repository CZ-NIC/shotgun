#!/usr/bin/env python3

# pylint: disable=wrong-import-order,wrong-import-position
import argparse
from collections import defaultdict
import ipaddress
import logging
import os
import statistics
import sys
import traceback
from typing import Dict, List, Optional, Union

import dns
import dns.exception
import dns.message

import dpkt
# Force matplotlib to use a different backend to handle machines without a display
import matplotlib
matplotlib.use('Agg')
import matplotlib.colors  # noqa
from matplotlib.lines import Line2D  # noqa
import matplotlib.pyplot as plt  # noqa


IP = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
SCALE_MAGIC = 10000


class MockRaw:
    def __init__(self, data: bytes) -> None:
        try:
            self.data = dpkt.ip.IP(data)
        except dpkt.UnpackError:
            self.data = dpkt.ip6.IP6(data)


LINK_TYPES = {
    dpkt.pcap.DLT_EN10MB: dpkt.ethernet.Ethernet,
    dpkt.pcap.DLT_LINUX_SLL: dpkt.sll.SLL,
    # dpkt.pcap.DLT_RAW can have 3 different values in dpkt - Gotta Catch Em All!
    12: MockRaw,
    14: MockRaw,
    101: MockRaw,
}


COLORS = [matplotlib.colors.to_rgba(c)
          for c in plt.rcParams['axes.prop_cycle'].by_key()['color']]


def init_plot(title):
    _, ax = plt.subplots(figsize=(8, 8))

    ax.set_xscale('log')
    ax.set_yscale('log')

    ax.grid(True, which='major')
    ax.grid(True, which='minor', linestyle='dotted', color='#DDDDDD')
    ax.set_ylim(0.00009, 110)

    ax.set_xlabel('Number of queries per client')
    ax.set_ylabel('Percentage of clients')
    ax.set_title(title)

    return ax


def create_filter(ips: Optional[List[IP]] = None) -> str:
    cap_filter = 'udp dst port 53'
    if ips:
        hosts = ['host {}'.format(ip) for ip in ips]
        cap_filter += ' and ({})'.format(' or '.join(hosts))
    return cap_filter


def count_client_queries(
            filename: str,
            ips: Optional[List[IP]] = None,
            since: float = 0,
            until: float = float('+inf'),
            include_malformed: bool = False
        ) -> Dict[bytes, int]:
    clients = defaultdict(int)  # type: Dict[bytes, int]

    with open(filename, 'rb') as fin:
        pcap = dpkt.pcap.Reader(fin)
        filter_ = create_filter(ips)
        logging.debug('using filter: "%s"', filter_)
        pcap.setfilter(filter_)
        if pcap.datalink() not in LINK_TYPES:
            logging.critical("Unsupported PCAP linktype: %d", pcap.datalink())
            sys.exit(1)

        parse = LINK_TYPES[pcap.datalink()]
        start = None
        end = None

        for ts, pkt in pcap:
            if start is None:
                start = ts + since
                end = ts + until

            if ts < start:
                continue
            if ts >= end:
                break

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

            if not include_malformed:
                try:
                    dns.message.from_wire(payload)
                except dns.exception.FormError:
                    continue

            # do mapping from original ip to client; new client otherwise
            clients[ip.src] += 1

    return clients


def plot_client_query_scatter(ax, clients: Dict[bytes, int], color):
    data = clients.values()

    x = []
    y = []
    s = []  # type: List[Union[float,int]]
    lmin = 0
    lmax = 10
    while lmax <= max(data):
        samples = list(n for n in data if lmin <= n < lmax)
        x.append(statistics.mean(samples))
        y.append(len(samples) / len(data) * 100)
        s.append(sum(samples))
        logging.info(
            '  [{:d}-{:d}) queries per client: {:d} ({:.2f} %) clients; {:d} queries total'
            .format(lmin, lmax, len(samples), y[-1], int(s[-1])))
        lmin = lmax
        lmax *= 10

    logging.info(
        '  total: {:d} clients; {:d} queries'
        .format(len(data), int(sum(s))))

    # normalize size
    s_tot = sum(s)
    s = [size * (SCALE_MAGIC / s_tot) for size in s]

    ax.scatter(x, y, s, color=color, alpha=0.5)


def main():
    logging.basicConfig(format='%(asctime)s %(levelname)8s  %(message)s', level=logging.DEBUG)
    logger = logging.getLogger('matplotlib')
    # set WARNING for Matplotlib
    logger.setLevel(logging.WARNING)

    parser = argparse.ArgumentParser(
        description='Analyze query distribution among clients in input pcap')
    parser.add_argument('pcap', nargs='+', help='PCAP(s) to analyze (output from pellet.py)')
    parser.add_argument('-o', '--output', type=str, default='clients.svg',
                        help='output filename (default: clients.svg)')
    parser.add_argument(
        '-r', '--resolvers', type=str, nargs='*',
        help='only use data flowing to specified addresses (IP/IPv6)')
    parser.add_argument('--since', type=float, default=0,
                        help='Omit data before this time (secs since test start)')
    parser.add_argument('--until', type=float, default=float('+inf'),
                        help='Omit data after this time (secs since test start)')
    parser.add_argument('-m', '--include-malformed', action='store_true',
                        help='include malformed packets')
    args = parser.parse_args()

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

    ax = init_plot("Query distribution among clients")
    handles = []
    lines = []
    labels = []

    for color, pcap in zip(COLORS, args.pcap):
        label = os.path.basename(pcap)
        logging.info('Processing: %s', label)
        try:
            clients = count_client_queries(pcap, ips, args.since, args.until,
                                           args.include_malformed)
        except FileNotFoundError as exc:
            logging.critical('%s', exc)
            sys.exit(1)
        except Exception as exc:
            logging.critical('uncaught exception: %s', exc)
            logging.debug(traceback.format_exc())
            sys.exit(1)
        else:
            labels.append(label)
            lines.append(Line2D([0], [0], color=color, lw=4))
            handles.append(plot_client_query_scatter(ax, clients, color))

    ax.legend(lines, labels, loc="lower left")
    plt.savefig(args.output, dpi=300)
    sys.exit(0)


if __name__ == '__main__':
    main()
