#!/usr/bin/env python3

import argparse
import csv
import logging
import math
import os
import sys
from typing import Dict, Tuple

# pylint: disable=wrong-import-order,wrong-import-position
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa

sinames = ['', ' k', ' M', ' G', ' T']


def init_plot(title):
    _, ax = plt.subplots(figsize=(8, 6))

    ax.set_xlabel('Time [s]')
    ax.set_ylabel('Packets per sampling period')
    ax.set_title(title)

    ax.grid(True, axis='x', which='both', linestyle='dotted')
    ax.grid(True, axis='y', which='both', linestyle='dotted')
    plt.minorticks_on()

    return ax


def plot(ax, data, label, since, until):
    xvalues = []
    yvalues = []
    for time_s, rate in data.items():
        xvalues.append(time_s)
        yvalues.append(rate)

    ax.plot(xvalues, yvalues, label=label, marker='x', linestyle='')
    ax.set_xlim(xmin=since)
    if math.isfinite(until):
        ax.set_xlim(xmax=until)


def parse_csv(csv_f, since: float, until: float) -> Tuple[float, Dict[float, float]]:
    """
    Parse CSV and return tuple (period, xydata).
    Period between samples is float or NaN if it varies by more than 1 ms.
    XY points are in format Dict[time_s] = period_packets value.
    """
    data = {}
    prev_time = None
    period = None
    for row in csv.DictReader(csv_f):
        now = float(row['time_s'])
        if now < since:
            continue
        if now > until:
            break

        if prev_time is not None:
            if not period:
                period = now - prev_time
            elif (not math.isnan(period)
                    and abs(period - abs(now - prev_time)) > 0.001):
                logging.warning('file %s: sampling period has changed between samples %f and %f',
                                csv_f.name, prev_time, now)
                period = float('nan')  # varies, undefined

        prev_time = now
        data[now] = float(row['period_packets'])

    if not prev_time or not period:
        raise ValueError('at least two data rows are required')

    return period, data


def main():
    logging.basicConfig(format='%(asctime)s %(levelname)8s  %(message)s', level=logging.DEBUG)
    logger = logging.getLogger('matplotlib')
    # set WARNING for Matplotlib
    logger.setLevel(logging.WARNING)

    parser = argparse.ArgumentParser(
            description="Plot packet rate")

    parser.add_argument('csv_file', nargs='+', help='CSV produced by count-packets-over-time.lua')
    parser.add_argument('-t', '--title', default='Packet rate in traffic sample',
                        help='Graph title')
    parser.add_argument('-o', '--output', default='packet_rate.svg',
                        help='Output graph filename')
    parser.add_argument('--since', type=float, default=0,
                        help='Omit data before this time (secs since test start)')
    parser.add_argument('--until', type=float, default=float('+inf'),
                        help='Omit data after this time (secs since test start)')

    args = parser.parse_args()

    # initialize graph
    ax = init_plot(args.title)

    for csv_path in args.csv_file:
        try:
            with open(csv_path) as f:
                period, xyrate = parse_csv(f, args.since, args.until)
        except FileNotFoundError as exc:
            logging.critical('%s', exc)
            sys.exit(1)

        name = os.path.splitext(os.path.basename(os.path.normpath(csv_path)))[0]
        if not math.isnan(period):
            period_str = f'sampling period {round(period, 4)} s'
        else:
            period_str = 'variable sampling period'

        plot(ax, xyrate, f'{name} ({period_str})', args.since, args.until)

    plt.legend()
    plt.savefig(args.output)


if __name__ == '__main__':
    main()
