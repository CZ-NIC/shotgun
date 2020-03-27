#!/usr/bin/env python3

# NOTE: Due to a weird bug, numpy is detected as a 3rd party module, while lmdb
#       is not and pylint complains about wrong-import-order.
#       Since these checks have to be disabled for matplotlib imports anyway, they
#       were moved a bit higher up to avoid the issue.
# pylint: disable=wrong-import-order,wrong-import-position
import argparse
import logging
import json
import math
import os
import sys

import numpy as np

# Force matplotlib to use a different backend to handle machines without a display
import matplotlib
import matplotlib.ticker as mtick
matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa


JSON_VERSION = 20200327
MIN_X_EXP = -1
MAX_X_EXP = 2

sinames = ['', ' k', ' M', ' G', ' T']


def siname(n):
    try:
        n = float(n)
    except ValueError:
        return n

    siidx = max(0, min(len(sinames)-1,
                       int(math.floor(0 if n == 0 else math.log10(abs(n))/3)))
                )
    return '{:.0f}{}'.format(n / 10**(3 * siidx), sinames[siidx])


def init_plot(title):
    # plt.rcParams["font.family"] = "monospace"
    _, ax = plt.subplots(figsize=(8, 8))

    ax.set_xscale('log')
    ax.xaxis.set_major_formatter(mtick.FormatStrFormatter('%s'))
    ax.set_yscale('log')
    ax.yaxis.set_major_formatter(mtick.FormatStrFormatter('%s'))

    ax.grid(True, which='major')
    ax.grid(True, which='minor', linestyle='dotted', color='#DDDDDD')

    ax.set_xlabel('Slowest percentile')
    ax.set_ylabel('Response time [ms]')
    ax.set_title(title)

    return ax


def get_percentile_latency(latency_data, percentile):
    total = sum(latency_data)
    ipercentile = math.ceil((100 - percentile) / 100 * total - 1)
    assert ipercentile <= total
    i = 0
    for latency, n in enumerate(latency_data):
        i += n
        if ipercentile <= i:
            return latency
    raise RuntimeError("percentile not found")


def plot_log_percentile_histogram(ax, latency, label):
    percentiles = np.logspace(MIN_X_EXP, MAX_X_EXP, num=100)
    ax.plot(
        percentiles, [get_percentile_latency(latency, pctl) for pctl in percentiles],
        lw=2, label=label)


def merge_latency(data, since=0, until=float('+inf')):
    since_ms = data['stats_sum']['since_ms'] + since * 1000
    until_ms = data['stats_sum']['since_ms'] + until * 1000

    latency = []
    requests = 0
    start = None
    end = None
    for stats in data['stats_periodic']:
        if stats['since_ms'] < since_ms:
            continue
        if stats['until_ms'] >= until_ms:
            break
        requests += stats['requests']
        if not latency:
            latency = list(stats['latency'])
            start = stats['since_ms']
        else:
            end = stats['until_ms']
            assert len(stats['latency']) == len(latency)
            for i, _ in enumerate(stats['latency']):
                latency[i] += stats['latency'][i]

    qps = requests / (end - start) * 1000  # convert from ms
    return latency, qps


def main():
    logging.basicConfig(format='%(asctime)s %(levelname)8s  %(message)s', level=logging.DEBUG)
    logger = logging.getLogger('matplotlib')
    # set WARNING for Matplotlib
    logger.setLevel(logging.WARNING)

    parser = argparse.ArgumentParser(
        description='Plot query response time histogram from shotgun results')
    parser.add_argument('json_file', nargs='+', help='Shotgun results JSON file(s)')
    parser.add_argument('-t', '--title', default='Response Latency',
                        help='Graph title')
    parser.add_argument('-o', '--output', type=str, default='latency.svg',
                        help='output filename (default: latency.svg)')
    parser.add_argument('--since', type=float, default=0,
                        help='Omit data before this time (secs since test start)')
    parser.add_argument('--until', type=float, default=float('+inf'),
                        help='Omit data after this time (secs since test start)')
    args = parser.parse_args()

    ax = init_plot(args.title)

    for json_path in args.json_file:
        try:
            with open(json_path) as f:
                data = json.load(f)
        except FileNotFoundError as exc:
            logging.critical('%s', exc)
            sys.exit(1)

        try:
            assert data['version'] == JSON_VERSION
        except (KeyError, AssertionError):
            logging.critical(
                "Older formats of JSON data aren't supported. "
                "Use older tooling or re-run the tests with newer shotgun.")
            sys.exit(1)

        dirname = os.path.basename(os.path.dirname(os.path.normpath(json_path)))
        latency, qps = merge_latency(data, args.since, args.until)
        label = '{} ({} QPS)'.format(dirname, siname(qps))
        plot_log_percentile_histogram(ax, latency, label)

    plt.legend()
    plt.savefig(args.output, dpi=300)


if __name__ == '__main__':
    main()
