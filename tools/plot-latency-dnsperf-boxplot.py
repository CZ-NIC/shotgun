#!/usr/bin/env python3

import argparse
import collections
import itertools
import json
import logging
import math
import os.path
import sys

# pylint: disable=wrong-import-order,wrong-import-position
import matplotlib
import matplotlib.colors as mcolors
from matplotlib.ticker import MultipleLocator
import matplotlib.patches as mpatches

matplotlib.use("Agg")
import matplotlib.pyplot as plt


JSON_VERSION = 20200527


StatRcode = collections.namedtuple("StatRcode", ["field", "label"])


sinames = ["", " k", " M", " G", " T"]


class NamedGroupAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if not isinstance(values, list) or len(values) <= 1:
            raise argparse.ArgumentError(
                self,
                "name required at first position, followed by one or more paths to JSON files",
            )
        groups = getattr(namespace, self.dest) or {}
        group_name = values[0]
        try:
            groups[group_name] = [
                argparse.FileType()(filename) for filename in values[1:]
            ]
        except argparse.ArgumentTypeError as ex:
            raise argparse.ArgumentError(self, ex)
        setattr(namespace, self.dest, groups)


def siname(n):
    try:
        n = float(n)
    except ValueError:
        return n

    siidx = max(
        0,
        min(len(sinames) - 1, int(math.floor(0 if n == 0 else math.log10(abs(n)) / 3))),
    )
    return "{:.0f}{}".format(n / 10 ** (3 * siidx), sinames[siidx])


def stat_field_rate(field):
    def inner(stats):
        if stats["requests"] == 0:
            return float("nan")
        if callable(field):
            field_val = field(stats)
        else:
            field_val = stats[field]
        return 100.0 * field_val / stats["requests"]

    return inner


def init_plot(title):
    scale = 0.3
    _, ax = plt.subplots(figsize=(33.87 * scale, 15.85 * scale))

    ax.set_xlabel("Time [s]")
    ax.set_ylabel("Latency [us]")
    #ax.set_title(title)

    #ax.grid(True, axis="x", which="major")

    #ax.yaxis.set_major_locator(MultipleLocator(10))
    ax.grid(True, axis="y", which="major")

    #ax.yaxis.set_minor_locator(MultipleLocator(2))
    ax.grid(True, axis="y", which="minor", linestyle="dashed", color="#DDDDDD")

    ax.set_yscale("log")

    ax.annotate('timeout', xy=(0, 5000000), xytext=(4, 5000000), xycoords='data',
        arrowprops=dict(color='gray', lw=1, fc='w', shrink=0.1),
        )

    return ax


def plot_response_rate(
    ax,
    label,
    idx,
    groups,
    color,
):
    print(label, color)
    group_cnt = len(groups)
    alpha = 0.5
    yvalues = groups[label].values()
    boxplot = ax.boxplot(
        yvalues,
        positions = list(range(idx, group_cnt * len(yvalues), group_cnt)),
        widths=0.5,
        showfliers=False,
        whis=(0, 100),
        #        notch=True, patch_artist=True,
        #        # colors
        #            boxprops=dict(facecolor=c, color=c, alpha=alpha),
        #            capprops=dict(color=c, alpha=alpha),
        #            whiskerprops=dict(color=c, alpha=alpha),
        #            flierprops=dict(color=c, markeredgecolor=c, alpha=alpha),
        #            medianprops=dict(color=c, alpha=alpha),
    )

    plt.setp(boxplot['boxes'], color=color)
    plt.setp(boxplot['whiskers'], color=color)
    plt.setp(boxplot['caps'], color=color)
    plt.setp(boxplot['medians'], color=color)


def main():
    logging.basicConfig(
        format="%(asctime)s %(levelname)8s  %(message)s", level=logging.DEBUG
    )
    logger = logging.getLogger("matplotlib")
    # set WARNING for Matplotlib
    logger.setLevel(logging.WARNING)

    parser = argparse.ArgumentParser(
        description="Plot response rate from shotgun experiment"
    )

    parser.add_argument(
        "-g",
        "--group",
        nargs="+",
        action=NamedGroupAction,
        default={},
        help="group_name json_file [json_file ...]; can be used multiple times",
    )
    parser.add_argument("json_file", nargs="*", help="Shotgun results JSON file(s)",
        type=argparse.FileType(),
                        )
    parser.add_argument(
        "-t", "--title", default="Response Latency over Time (min, 25perc, median, 75perc, max incl. timeouts)", help="Graph title"
    )
    parser.add_argument(
        "-o", "--output", default="latency_over_time.svg", help="Output graph filename"
    )
    args = parser.parse_args()
    if not args.json_file and not args.group:
        parser.error(
            "at least one input JSON file required (individually or in a group)"
        )
    # group name -> second -> list of raw values
    groups = collections.defaultdict(lambda: collections.defaultdict(list))
    try:
        for json_file in args.json_file:
            logging.info("processing %s", json_file.name)
            #name = os.path.splitext(os.path.basename(os.path.normpath(json_file.name)))[0]
            name = json_file.name
            process_file(json_file, groups[name])

        for name, group_files in args.group.items():
            for json_file in group_files:
                logging.info("processing group %s: %s", name, json_file.name)
                process_file(json_file, groups[name])
    except (FileNotFoundError, NotImplementedError) as exc:
        logging.critical("%s", exc)
        sys.exit(1)

    # initialize graph
    ax = init_plot(args.title)

    legend = []
    ticks = None
    if len(groups) > 1:
        colors = list(mcolors.TABLEAU_COLORS.keys()) + list(mcolors.BASE_COLORS.keys())
        colors.remove("w")  # avoid white line on white background
    else:
        colors = ['black']
    for group, color in itertools.zip_longest(
        enumerate(groups.keys()), colors[: len(groups)]
    ):
        group_idx, group_name = group
        ticks = groups[group_name].keys()
        plot_response_rate(ax, group_name, group_idx, groups, color)
        legend.append(mpatches.Patch(color=color, label=group_name))

    plt.legend(handles=legend)

    ticks = list(sorted(ticks))
    plt.xticks([(len(groups) - 1) / 2 + n for n in range(0, len(ticks) * len(groups), len(groups))], ticks, rotation = "vertical")
    plt.xlim(-1, len(ticks)*len(groups) + 1)
    #ax.set_ylim(0)

    #plt.legend()
    plt.tight_layout()
    plt.savefig(args.output)

def buckets_to_list(buckets):
    data = []
    for lat_min, lat_max, count in buckets:
        lat_avg = (lat_min + lat_max) / 2
        data += [lat_avg] * count
    return data


def append_group_data(file_data, min_timespan, group_data):
    stats_periodic = file_data["stats_periodic"]
    time_offset = stats_periodic[0]["since_ms"]

    for stats in stats_periodic:
        timespan = stats["until_ms"] - stats["since_ms"]
        if timespan < min_timespan:
            continue
        time = (stats["until_ms"] - time_offset) / 1000
        yvals = buckets_to_list(stats['answer_latency'].get('buckets', []))
        xval = int(time)
        group_data[xval].extend(yvals)
        if stats['timeouts']:
            # attribute timeouts correctly
            xval = xval - (file_data['timeout'] / 1e6)
            group_data[xval].extend(stats['timeouts'] * [file_data['timeout'] + 1])


def process_file(json_file, sec_to_vals):
    data = json.load(json_file)
    try:
        assert data["version"] == JSON_VERSION
    except (KeyError, AssertionError):
        raise NotImplementedError(
            "Older formats of JSON data aren't supported. "
            "Use older tooling or re-run the tests with newer shotgun."
        ) from None

    if data["discarded"] != 0:
        logging.warning("%d discarded packets may skew results!", data["discarded"])

    timespan = (data["stats_sum"]["until_ms"] - data["stats_sum"]["since_ms"]) / 1000
    #name = os.path.splitext(os.path.basename(os.path.normpath(json_path)))[0]
    label = json_file.name
    min_timespan = data["stats_interval_ms"] / 2
    append_group_data(data, min_timespan, sec_to_vals)

if __name__ == "__main__":
    main()
