#!/usr/bin/env python3

# NOTE: Due to a weird bug, numpy is detected as a 3rd party module, while lmdb
#       is not and pylint complains about wrong-import-order.
#       Since these checks have to be disabled for matplotlib imports anyway, they
#       were moved a bit higher up to avoid the issue.
# pylint: disable=wrong-import-order,wrong-import-position
import argparse
import collections
import itertools
import logging
import math
import os
import re

import numpy as np

# Force matplotlib to use a different backend to handle machines without a display
import matplotlib
import matplotlib.ticker as mtick

matplotlib.use("Agg")
import matplotlib.pyplot as plt

import mplhlpr.styles

import _plot_common as pc

MIN_X = 1
MAX_X = 100


def init_plot(title):
    _, ax = plt.subplots()

    fmt = mtick.FormatStrFormatter("%g")
    maj_loc = mtick.LogLocator(subs=[(x / 10) for x in range(0, 10)])

    ax.set_xscale("log")
    ax.xaxis.set_major_formatter(fmt)
    ax.xaxis.set_major_locator(maj_loc)
    ax.set_yscale("log")
    ax.yaxis.set_major_formatter(fmt)
    ax.yaxis.set_major_locator(maj_loc)

    ax.grid(True, which="major")
    ax.grid(True, which="minor")

    ax.margins(x=0)

    ax.set_xlabel("Slowest percentile")
    ax.set_ylabel("Response time [ms]")
    mplhlpr.styles.ax_set_title(ax, title)

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


def get_xy_from_histogram(latency_histogram):
    boundaries, counts = latency_histogram

    count_sum = sum(counts)
    acc = 0
    x_percentages = [100.0]

    for count in counts:
        acc += count
        x_percentages.append(100 - (acc / count_sum) * 100)

    y_latency_buckets = [0] + boundaries

    return x_percentages, y_latency_buckets


def merge_latency(data, since=0, until=float("+inf")):
    """generate latency histogram for given period"""
    header, stats_sum, stats_periodic = data
    # add 100ms tolarence for interval beginning / end
    since_ms = stats_sum["since"] + since * 1000 - 100
    until_ms = stats_sum["since"] + until * 1000 + 100

    latency_counts = []
    requests = 0
    start = None
    end = None
    for stats in stats_periodic:
        if stats["since"] < since_ms:
            continue
        if stats["until"] >= until_ms:
            break
        requests += stats["queries"]
        end = stats["until"]
        if not latency_counts:
            latency_counts = list(stats["response_latency"]["counts"])
            start = stats["since"]
        else:
            assert len(stats["response_latency"]["counts"]) == len(latency_counts)
            for i, _ in enumerate(stats["response_latency"]["counts"]):
                latency_counts[i] += stats["response_latency"]["counts"][i]

    if not latency_counts:
        raise RuntimeError("no samples matching this interval")

    boundaries = header["latency_bucket_boundaries"]
    boundaries.append(header["timeout"])
    latency = (boundaries, latency_counts)
    qps = requests / (end - start) * header["time_units_per_sec"]
    return latency, qps


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


LINE_STYLES = matplotlib.cbook.ls_mapper.values()


class LineStyleAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        try:
            regex = re.compile(values[0])
        except re.error as e:
            raise argparse.ArgumentError(
                self, f"first linestyle argument is not a regex: {e}"
            )
        style = values[1]
        if style not in LINE_STYLES:
            raise argparse.ArgumentError(
                self,
                f"second linestyle argument must be one of: {', '.join(LINE_STYLES)}",
            )
        linestyles = getattr(namespace, self.dest) or {}
        linestyles[regex] = style
        setattr(namespace, self.dest, linestyles)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Plot query response time histogram from shotgun results"
    )
    parser.add_argument(
        "-t",
        "--title",
        default="Response Latency",
        help="Graph title"
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="latency.svg",
        help="output filename (default: latency.svg)",
    )
    parser.add_argument(
        "--since",
        type=float,
        default=0,
        help="Omit data before this time (secs since test start)",
    )
    parser.add_argument(
        "--until",
        type=float,
        default=float("+inf"),
        help="Omit data after this time (secs since test start)",
    )
    parser.add_argument(
        "--linestyle",
        nargs=2,
        action=LineStyleAction,
        default={},
        help=(
            "change style for series with names matching regex; "
            "name_regex linestyle_name (can be specified multiple times)"
        ),
    )

    input_args = parser.add_argument_group(
        title="input data",
        description="Shotgun result JSON file(s) to plot as individual data sets"
        " or groups aggregated to min/avg/max.",
    )
    input_args.add_argument(
        "-g",
        "--group",
        nargs="+",
        action=NamedGroupAction,
        default={},
        help="group_name json_file [json_file ...]; can be used multiple times",
    )
    input_args.add_argument(
        "json_file",
        nargs="*",
        type=argparse.FileType(),
        help="JSON file(s) to plot individually",
    )

    args = parser.parse_args()
    if not args.json_file and not args.group:
        parser.error(
            "at least one input JSON file required (individually or in a group)"
        )
    return args


def main():
    logging.basicConfig(
        format="%(asctime)s %(levelname)8s  %(message)s", level=logging.DEBUG
    )
    logger = logging.getLogger("matplotlib")
    # set WARNING for Matplotlib
    logger.setLevel(logging.WARNING)

    mplhlpr.styles.configure_mpl_styles()

    args = parse_args()

    groups = collections.defaultdict(list)
    ax = init_plot(args.title)
    min_x = MIN_X

    for json_file in args.json_file:
        logging.info("processing %s", json_file.name)
        header, stats_sum, stats_periodic = pc.load_json_lines_file(json_file)
        name = os.path.splitext(os.path.basename(os.path.normpath(json_file.name)))[0]
        groups[name].append([header, stats_sum, stats_periodic])

    for name, group_files in args.group.items():
        for json_file in group_files:
            logging.info("processing group %s: %s", name, json_file.name)
            header, stats_sum, stats_periodic = pc.load_json_lines_file(json_file)
            groups[name].append([header, stats_sum, stats_periodic])

    for name, group_data in groups.items():
        pos_inf = float("inf")
        neg_inf = float("-inf")
        group_x = []  # we use the same X coordinates for all runs
        group_ymin = []
        group_ymax = []
        group_ysum = []
        for run_data in group_data:
            latency, qps = merge_latency(run_data, args.since, args.until)
            label = f"{name} ({pc.siname(qps)} QPS)"
            group_x, run_y = get_xy_from_histogram(latency)
            if len(group_data) == 1:  # no reason to compute aggregate values
                group_ysum = run_y
                break
            group_ysum = [
                old + new
                for old, new in itertools.zip_longest(group_ysum, run_y, fillvalue=0)
            ]
            group_ymin = [
                min(old, new)
                for old, new in itertools.zip_longest(
                    group_ymin, run_y, fillvalue=pos_inf
                )
            ]
            group_ymax = [
                max(old, new)
                for old, new in itertools.zip_longest(
                    group_ymax, run_y, fillvalue=neg_inf
                )
            ]
        if len(group_data) > 1:
            group_yavg = [ysum / len(group_data) for ysum in group_ysum]
            ax.fill_between(group_x, group_ymin, group_ymax, alpha=0.2)
        else:
            group_yavg = group_ysum
        linestyle = "solid"
        for name_re, style in args.linestyle.items():
            if name_re.search(name):
                linestyle = style
        if len(group_x) < 15:
            marker = "o"
        else:
            marker = ""

        if len(group_x) >= 2:
            last_pct = group_x[-2]
            min_x = last_pct if 0 < last_pct < min_x else min_x
        ax.set_xlim(left=min_x, right=MAX_X)
        ax.plot(group_x, group_yavg, lw=2, label=label, marker=marker, linestyle=linestyle)

    plt.legend()
    plt.savefig(args.output)


if __name__ == "__main__":
    main()
