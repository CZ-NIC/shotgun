#!/usr/bin/python3

import argparse
import logging
import random
import sys
import traceback
from typing import Dict

import dpkt.pcap


def scale_pcap(
            filename_in: str,
            filename_out: str,
            factor: float
        ) -> None:
    if factor <= 0:
        raise RuntimeError("invalid factor: must be larger than 0")
    if factor > 1:
        raise NotImplementedError("scaling up isn't implemented yet")

    clients = {}  # type: Dict[bytes, bool]

    with open(filename_in, 'rb') as fin:
        pcap_in = dpkt.pcap.Reader(fin)
        if pcap_in.datalink() != dpkt.pcap.DLT_RAW:
            logging.critical("input PCAP must be output from pellet.py")
            sys.exit(1)

        with open(filename_out, 'wb') as fout:
            try:
                pcap_out = dpkt.pcap.Writer(
                    fout, snaplen=66000, linktype=dpkt.pcap.DLT_RAW)

                for ts, pkt in pcap_in:
                    ip = dpkt.ip6.IP6(pkt)

                    try:
                        write = clients[ip.src]
                    except KeyError:
                        write = random.random() < factor
                        clients[ip.src] = write
                    if write:
                        pcap_out.writepkt(pkt, ts=ts)
            finally:
                pcap_out.close()


def main():
    parser = argparse.ArgumentParser(
        description='scale (up or down) the number of clients in pellet PCAP')
    parser.add_argument('pcap_in', type=str, help='input PCAP file to process')
    parser.add_argument('pcap_out', type=str, help='output PCAP to write')
    parser.add_argument(
        '-f', '--factor', type=float, default=0.5,
        help='the factor to which number of clients is scaled to')
    parser.add_argument(
        '-s', '--seed', type=int, default=0,
        help='seed for PRNG')

    args = parser.parse_args()

    logging.basicConfig(
        format='%(asctime)s %(levelname)8s  %(message)s', level=logging.DEBUG)
    random.seed(args.seed)

    try:
        scale_pcap(args.pcap_in, args.pcap_out, args.factor)
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
