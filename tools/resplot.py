#!/usr/bin/python3

from abc import ABC, abstractmethod
import argparse
import collections
import json
import logging
from pathlib import Path
from pprint import pprint
import re
import sys

# pylint: disable=wrong-import-order,wrong-import-position
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa


def init_plot(title):
    fig, ax = plt.subplots(figsize=(16, 9))

    ax.set_xlabel('Time [s]')
    #ax.set_ylabel('Packets per sampling period')
    ax.set_title(title)

    ax.grid(True, axis='x', which='both', linestyle='dotted')
    ax.grid(True, axis='y', which='both', linestyle='dotted')
    plt.minorticks_on()

    return fig, ax


def plot(ax, stats, name, time_zero, until_relative, avg_interval):
    xvalues = []
    yvalues = []
    if not avg_interval:
        for _, time_s, rate in stats:
            reltime = time_s - time_zero
            if reltime > 0:
                xvalues.append(reltime)
                yvalues.append(rate)
    else:
        cur_interval_start = None
        sum_count = 0
        sum_values = 0
        for time_from, time_to, rate in stats:
            if cur_interval_start == None:
                cur_interval_start = time_from
            if time_to - cur_interval_start < avg_interval:
                sum_count += 1
                sum_values += rate
            else:
                xvalues.append(cur_interval_start + (time_to - cur_interval_start) / 2 - time_zero)
                yvalues.append(sum_values / sum_count)
                cur_interval_start = None
                sum_count = 0
                sum_values = 0
                # TODO: last point

    ax.set_xlim(xmin=0, xmax=until_relative)
    ax.plot(xvalues, yvalues, label=name, marker='x', linestyle='dotted')


def normalize_chart_id(orig_id: str):
    if not 'docker-' in orig_id:
        return orig_id
    return re.sub('docker-.*scope', 'docker', orig_id)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(
        description="Plot resource usage")

    parser.add_argument('result_dirs', nargs='+', help='Ansible result dirs')
    parser.add_argument('--average', type=float, help='interval to average over')
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    logging.getLogger('matplotlib').setLevel(logging.WARNING)
    charts = {}

    for dirname in args.result_dirs:
        with open(Path(dirname) / 'resmon-extracted.json', 'r') as statfile:
            stats = json.load(statfile)
        with open(Path(dirname) / 'results-shotgun/data/UDP.json') as shotgun_json:
            shotgun_res = json.load(shotgun_json)
        # offset for time 0
        time_zero = shotgun_res['stats_sum']['since_ms'] / 1000
        time_end = shotgun_res['stats_sum']['until_ms'] / 1000
        #pprint(stats)
        for cgrp in stats:
            for stat in stats[cgrp]:
                chart_id = normalize_chart_id(f'{stat}-{cgrp}')
                ### TODO: handle multiple groups with the same set of names (put cgrp name in title & filename?)
                #if (('net.' in stat or 'disk.' in stat) and (stat not in {'rx.packets', 'rx.drop', 'tx.packets', 'tx.drop'}) or 
                if (stat.startswith('cpu') and not stat.startswith('cpu.')):
                    continue
                # skip all-zeros
                if sum(yval for _, _, yval in stats[cgrp][stat]) == 0:
                    continue
                if chart_id not in charts:
                    charts[chart_id] = init_plot(chart_id)

                logging.info('plotting %s: %s', dirname, chart_id)
                plot(charts[chart_id][1], stats[cgrp][stat], dirname, time_zero, time_end - time_zero + 10, args.average)

    for chart_id, chart_objs in charts.items():
        fig = chart_objs[0]
        fig.legend()
        fig.tight_layout()
        logging.info('saving %s', chart_id)
        fig.savefig(f'{chart_id}.svg')
        #fig.close()


