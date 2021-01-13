#!/usr/bin/env python3

# pylint: disable=wrong-import-order,wrong-import-position
import argparse
import csv
import logging
import os
import statistics
import sys
import traceback
from typing import Dict, List, Union

# Force matplotlib to use a different backend to handle machines without a display
import matplotlib
matplotlib.use('Agg')
import matplotlib.colors  # noqa
from matplotlib.lines import Line2D  # noqa
import matplotlib.pyplot as plt  # noqa


SCALE_MAGIC = 10000


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


def count_client_queries(
            filename: str,
        ) -> Dict[str, int]:
    with open(filename, newline='') as csvfile:
        reader = csv.DictReader(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_NONNUMERIC)
        return {row['ip']: int(row['packets']) for row in reader}


def plot_client_query_scatter(ax, clients: Dict[str, int], color):
    data = clients.values()

    x = []
    y = []
    s = []  # type: List[Union[float,int]]
    sanity_nsamples = 0
    step_multiplier = 10
    lmin = 0
    lmax = step_multiplier
    while lmin <= max(data):
        samples = list(n for n in data if lmin <= n < lmax)
        x.append(statistics.mean(samples))
        y.append(len(samples) / len(data) * 100)
        s.append(sum(samples))
        logging.info(
            '  [{:d}-{:d}) queries per client: {:d} ({:.2f} %) clients; {:d} queries total'
            .format(lmin, lmax, len(samples), y[-1], int(s[-1])))
        lmin = lmax
        lmax *= step_multiplier

    assert sanity_nsamples == len(data)
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
    parser.add_argument('csv', nargs='+',
                        help='CSV(s) to visualize (output from count-packets-per-ip.lua)')
    parser.add_argument('-o', '--output', type=str, default='clients.svg',
                        help='output filename (default: clients.svg)')
    args = parser.parse_args()

    ax = init_plot("Query distribution among clients")
    handles = []
    lines = []
    labels = []

    for color, csv_inf in zip(COLORS, args.csv):
        label = os.path.basename(csv_inf)
        logging.info('Processing: %s', label)
        try:
            clients_qps = count_client_queries(csv_inf)
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
            handles.append(plot_client_query_scatter(ax, clients_qps, color))

    ax.legend(lines, labels, loc="lower left")
    plt.savefig(args.output, dpi=300)
    sys.exit(0)


if __name__ == '__main__':
    main()
