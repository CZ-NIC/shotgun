#!/usr/bin/env python3

import argparse
import collections
import json
import logging
import math
import os.path

# pylint: disable=wrong-import-order,wrong-import-position
import matplotlib
from matplotlib.ticker import MultipleLocator
matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa


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


def merge_data(thread_data):
    out = {
        'discarded': 0,
        'stats_sum': collections.defaultdict(int),
        'stats_periodic': [],
    }

    def add_stats(src, dst):
        for key, val in src.items():
            dst[key] += val

    for data in thread_data:
        out['discarded'] += data['discarded']
        add_stats(data['stats_sum'], out['stats_sum'])
        for i in range(len(data['stats_periodic'])):
            try:
                out['stats_periodic'][i]
            except IndexError:
                out['stats_periodic'].append(collections.defaultdict(int))
                assert len(out['stats_periodic']) == (i + 1)
            add_stats(data['stats_periodic'][i], out['stats_periodic'][i])

    return out


def stat_field_rate(field):
    def inner(stats):
        return 100.0 * stats[field] / (stats['requests'] + stats['ongoing'])
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


def plot_response_rate(ax, data, stats_interval, label, skip_last=True, eval_func=None):
    stats_periodic = data['stats_periodic'][:-1] if skip_last else data['stats_periodic']

    if not eval_func:
        eval_func = response_rate

    xvalues = list(range(
        stats_interval,
        len(stats_periodic) * stats_interval + 1,
        stats_interval))
    yvalues = []
    for stats in stats_periodic:
        yvalues.append(eval_func(stats))

    ax.plot(xvalues, yvalues, label=label, marker='o', linestyle='--')


def main():
    logging.basicConfig(format='%(asctime)s %(levelname)8s  %(message)s', level=logging.DEBUG)
    logger = logging.getLogger('matplotlib')
    # set WARNING for Matplotlib
    logger.setLevel(logging.WARNING)

    parser = argparse.ArgumentParser(
        description="Plot time series from shotgun experiment")

    parser.add_argument('input_dir', nargs='+',
                        help='Directory with results; name will be used as label')
    parser.add_argument('-t', '--title', default='Response Rate over Time',
                        help='Graph title')
    parser.add_argument('-S', '--stats-interval', default=5, type=int,
                        help='Statistics collection interval')
    parser.add_argument('-o', '--output', default='response_rate.svg',
                        help='Output graph filename')
    parser.add_argument('-r', '--rcode', nargs='*', type=int,
                        help='RCODE(s) to plot in addition to answer rate')
    args = parser.parse_args()

    # initialize graph
    ax = init_plot(args.title)

    for in_dir in args.input_dir:
        thread_data = []

        for filename in os.listdir(in_dir):
            if not filename.endswith('.json'):
                continue

            path = os.path.join(in_dir, filename)
            with open(path) as f:
                thread_data.append(json.load(f))

        # merge data
        data = merge_data(thread_data)
        if data['discarded'] != 0:
            logging.warning("%d discarded packets may skew results!", data['discarded'])

        label = os.path.basename(os.path.normpath(in_dir))
        if len(data['stats_periodic']) > 1:
            qps = data['stats_sum']['requests'] / \
                (args.stats_interval * (len(data['stats_periodic']) - 1))
            label = '{} ({} QPS)'.format(label, siname(qps))

        plot_response_rate(
            ax,
            data,
            args.stats_interval,
            label)

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
                    args.stats_interval,
                    rcode_label,
                    eval_func=eval_func)

    plt.legend()
    plt.savefig(args.output)


if __name__ == '__main__':
    main()
