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
    _, ax = plt.subplots(figsize=(16, 9))

    ax.set_xlabel('Time [s]')
    #ax.set_ylabel('Packets per sampling period')
    ax.set_title(title)

    ax.grid(True, axis='x', which='both', linestyle='dotted')
    ax.grid(True, axis='y', which='both', linestyle='dotted')
    plt.minorticks_on()

    return ax


def plot(stats, name, time_zero, until_relative, avg_interval):
    logging.info('plotting %s', name)
    ax = init_plot(name)

    xvalues = []
    yvalues = []
    if not avg_interval:
        for _, time_s, rate in stats:
            xvalues.append(time_s - time_zero)
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

    plt.savefig(f'{name}.svg')
    plt.close('all')



if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    logging.getLogger('matplotlib').setLevel(logging.WARNING)
    with open(sys.argv[1], 'r') as shotfile:
        shotgun_res = json.load(shotfile)
    if len(sys.argv) > 2:
        average = float(sys.argv[2])
    else:
        average = None
    # offset for time 0
    time_zero = shotgun_res['stats_sum']['since_ms'] / 1000
    time_end = shotgun_res['stats_sum']['until_ms'] / 1000
    with open('resmon-extracted.json', 'r') as statfile:
        stats = json.load(statfile)
    #pprint(stats)
    for cgrp in stats:
        for stat in stats[cgrp]:
            ### TODO: handle multiple groups with the same set of names (put cgrp name in title & filename?)
            if ('net.' in stat or 'disk.' in stat) and (stat not in {'net.ens5.rx.packets', 'net.ens5.rx.drop', 'net.ens5.tx.packets', 'net.ens5.tx.drop'}):
            #if not 'usage' in stat:
                continue
            plot(stats[cgrp][stat], f'{stat}-{cgrp}', time_zero, time_end - time_zero + 10, average)
