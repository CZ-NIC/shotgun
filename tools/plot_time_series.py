#!/usr/bin/env python3

import argparse
import collections
import json
import logging
import math
import os.path
import sys

# pylint: disable=wrong-import-order,wrong-import-position
import matplotlib
from matplotlib.ticker import MultipleLocator
matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa


JSON_VERSION = 20200527


StatRcode = collections.namedtuple('StatRcode', ['field', 'label'])

RCODES = {
    0: StatRcode('rcode_noerror', 'NOERROR'),
    1: StatRcode('rcode_formerr', 'FORMERR'),
    2: StatRcode('rcode_servfail', 'SERVFAIL'),
    3: StatRcode('rcode_nxdomain', 'NXDOMAIN'),
    4: StatRcode('rcode_notimp', 'NOTIMP'),
    5: StatRcode('rcode_refused', 'REFUSED'),
    6: StatRcode('rcode_yxdomain', 'YXDOMAIN'),
    7: StatRcode('rcode_yxrrset', 'YXRRSET'),
    8: StatRcode('rcode_nxrrset', 'NXRRSET'),
    9: StatRcode('rcode_notauth', 'NOTAUTH'),
    10: StatRcode('rcode_notzone', 'NOTZONE'),
    16: StatRcode('rcode_badvers', 'BADVERS'),
    17: StatRcode('rcode_badkey', 'BADKEY'),
    18: StatRcode('rcode_badtime', 'BADTIME'),
    19: StatRcode('rcode_badmode', 'BADMODE'),
    20: StatRcode('rcode_badname', 'BADNAME'),
    21: StatRcode('rcode_badalg', 'BADALG'),
    22: StatRcode('rcode_badtrunc', 'BADTRUNC'),
    23: StatRcode('rcode_badcookie', 'BADCOOKIE'),
}

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


def stat_field_rate(field):
    def inner(stats):
        return 100.0 * stats[field] / stats['requests']
    return inner


response_rate = stat_field_rate('answers')


def init_plot(title):
    _, ax = plt.subplots(figsize=(8, 6))

    ax.set_xlabel('Time [s]')
    ax.set_ylabel('Response Rate [%]')
    ax.set_title(title)

    ax.grid(True, axis='x', which='major')

    ax.yaxis.set_major_locator(MultipleLocator(10))
    ax.grid(True, axis='y', which='major')

    ax.yaxis.set_minor_locator(MultipleLocator(2))
    ax.grid(True, axis='y', which='minor', linestyle='dashed', color='#DDDDDD')

    return ax


def set_axes_limits(ax):
    bottom, top = ax.get_ylim()
    bottom = math.floor(bottom / 10) * 10
    top = math.ceil(top / 10) * 10
    top = top + 1 if top <= 100 else 101
    bottom = bottom - 1 if bottom >= 0 else -1
    ax.set_ylim(bottom, top)


def plot_response_rate(ax, data, label, eval_func=None, min_timespan=0):
    stats_periodic = data['stats_periodic']
    time_offset = stats_periodic[0]['since_ms']

    if not eval_func:
        eval_func = response_rate

    xvalues = []
    yvalues = []
    for stats in stats_periodic:
        timespan = stats['until_ms'] - stats['since_ms']
        if timespan < min_timespan:
            continue
        time = (stats['until_ms'] - time_offset) / 1000
        xvalues.append(time)
        yvalues.append(eval_func(stats))

    ax.plot(xvalues, yvalues, label=label, marker='o', linestyle='--')


def main():
    logging.basicConfig(format='%(asctime)s %(levelname)8s  %(message)s', level=logging.DEBUG)
    logger = logging.getLogger('matplotlib')
    # set WARNING for Matplotlib
    logger.setLevel(logging.WARNING)

    parser = argparse.ArgumentParser(
        description="Plot time series from shotgun experiment")

    parser.add_argument('json_file', nargs='+', help='Shotgun results JSON file(s)')
    parser.add_argument('-t', '--title', default='Response Rate over Time',
                        help='Graph title')
    parser.add_argument('-o', '--output', default='response_rate.svg',
                        help='Output graph filename')
    parser.add_argument('-r', '--rcode', nargs='*', type=int,
                        help='RCODE(s) to plot in addition to answer rate')
    args = parser.parse_args()

    # initialize graph
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

        if data['discarded'] != 0:
            logging.warning("%d discarded packets may skew results!", data['discarded'])

        timespan = (data['stats_sum']['until_ms'] - data['stats_sum']['since_ms']) / 1000
        qps = data['stats_sum']['requests'] / timespan
        dirname = os.path.basename(os.path.dirname(os.path.normpath(json_path)))
        label = '{} ({} QPS)'.format(dirname, siname(qps))
        min_timespan = data['stats_interval_ms'] / 2

        plot_response_rate(
            ax,
            data,
            label,
            min_timespan=min_timespan)

        if args.rcode:
            for rcode in args.rcode:
                try:
                    stat_rcode = RCODES[rcode]
                except KeyError:
                    logging.error("Unknown RCODE: %d", rcode)
                    continue

                eval_func = stat_field_rate(stat_rcode.field)
                rcode_label = '{} {}'.format(label, stat_rcode.label)

                plot_response_rate(
                    ax,
                    data,
                    rcode_label,
                    eval_func=eval_func,
                    min_timespan=min_timespan)

    set_axes_limits(ax)

    plt.legend()
    plt.savefig(args.output)


if __name__ == '__main__':
    main()
