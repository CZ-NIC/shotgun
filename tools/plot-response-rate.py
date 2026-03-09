#!/usr/bin/env python3

import argparse
import collections
import itertools
import logging
import math
import os.path
import sys

# pylint: disable=wrong-import-order,wrong-import-position
import matplotlib
import matplotlib.colors as mcolors
from matplotlib.ticker import MultipleLocator

matplotlib.use("Agg")
import matplotlib.pyplot as plt

import mplhlpr.styles
import _plot_common as pc

def stat_field_rate(field):
    def inner(stats):
        if stats["queries"] == 0:
            return float("nan")
        if callable(field):
            field_val = field(stats)
        else:
            field_val = stats[field]
        return 100.0 * field_val / stats["queries"]

    return inner


response_rate = stat_field_rate("responses")


def rcode_rate(rcodes):
    if isinstance(rcodes, str):
        rcodes = [rcodes]
    def inner(stats):
        if stats["queries"] == 0:
            return float("nan")
        total = sum(stats.get("response_rcodes", {}).get(r, 0) for r in rcodes)
        return 100.0 * total / stats["queries"]
    return inner


def init_plot(title):
    _, ax = plt.subplots()

    ax.set_xlabel("Time [s]")
    ax.set_ylabel("Response Rate [%]")
    mplhlpr.styles.ax_set_title(ax, title)

    ax.grid(True, axis="x", which="major")

    ax.yaxis.set_major_locator(MultipleLocator(10))
    ax.grid(True, axis="y", which="major")

    ax.yaxis.set_minor_locator(MultipleLocator(2))
    ax.grid(True, axis="y", which="minor")

    return ax


def set_axes_limits(ax):
    bottom, top = ax.get_ylim()
    bottom = math.floor(bottom / 10) * 10
    top = math.ceil(top / 10) * 10
    top = top + 1 if top <= 100 else 101
    bottom = bottom - 1 if bottom >= 0 else -1
    ax.set_ylim(bottom, top)


def plot_response_rate(
    ax,
    stats_periodic,
    label,
    eval_func=None,
    min_timespan=0,
    min_rate=0,
    marker=None,
    linestyle=None,
    color=None,
):
    time_offset = stats_periodic[0]["since"]

    if not eval_func:
        eval_func = response_rate

    xvalues = []
    yvalues = []
    for stats in stats_periodic:
        timespan = stats["until"] - stats["since"]
        if timespan < min_timespan:
            continue
        time = (stats["until"] - time_offset) / 1000
        xvalues.append(time)
        yvalues.append(eval_func(stats))

    if not min_rate or max(yvalues) >= min_rate:
        ax.plot(
            xvalues,
            yvalues,
            label=label,
            marker=marker,
            linestyle=linestyle,
            color=color,
        )


def main():
    logging.basicConfig(
        format="%(asctime)s %(levelname)8s  %(message)s", level=logging.DEBUG
    )
    logger = logging.getLogger("matplotlib")
    # set WARNING for Matplotlib
    logger.setLevel(logging.WARNING)

    mplhlpr.styles.configure_mpl_styles()

    parser = argparse.ArgumentParser(
        description="Plot response rate from shotgun experiment"
    )

    parser.add_argument(
        "json_file",
        nargs="+",
        help="Shotgun results JSON file(s)")
    parser.add_argument(
        "-t",
        "--title",
        default="Response Rate over Time",
        help="Graph title"
    )
    parser.add_argument(
        "-o",
        "--output",
        default="response_rate.svg",
        help="Output graph filename"
    )
    parser.add_argument(
        "-T",
        "--skip-total",
        action="store_const",
        const="True",
        help="Skip line for total response rate",
    )
    parser.add_argument(
        "-r",
        "--rcode",
        nargs="*",
        type=str,
        help="RCODE(s) to plot in addition to answer rate",
    )
    parser.add_argument(
        "-R",
        "--rcodes-above-pct",
        type=float,
        help="Add RCODE(s) representing more than the specified percentage "
        "of all answers (short spikes might not be shown if the percentage "
        "is too high)",
    )
    parser.add_argument(
        "-i",
        "--ignore-rcodes-rate-pct",
        type=float,
        help="Remove RCODE(s) whose response rate never exceeds the specified value "
        "(a single spike will cause the RCODE to show)",
    )
    parser.add_argument(
        "-s",
        "--sum-rcodes",
        nargs="*",
        type=str,
        help="Plot sum of RCODE(s)"
    )
    args = parser.parse_args()

    # initialize graph
    ax = init_plot(args.title)

    colors = list(mcolors.TABLEAU_COLORS.keys()) + list(mcolors.BASE_COLORS.keys())
    colors.remove("w")  # avoid white line on white background
    for json_path, color in itertools.zip_longest(
        args.json_file, colors[: len(args.json_file)]
    ):
        try:
            process_file(json_path, color, args, ax)
        except (FileNotFoundError, NotImplementedError) as exc:
            logging.critical("%s: %s", json_path, exc)
            sys.exit(1)

    set_axes_limits(ax)

    plt.legend()
    plt.savefig(args.output)


def process_file(json_path, json_color, args, ax):
    header, stats_sum, stats_periodic = pc.load_json_lines_file(json_path)

    if stats_sum['discarded'] != 0:
        proportion_all_perc = stats_sum['discarded'] / stats_sum['queries'] * 100
        proportion_one_sec_perc = (
            stats_sum['discarded']
            / min(
                sample["queries"]
                for sample in stats_periodic
                if sample["queries"] > 0
            )
            * 100
        )
        logging.warning(
            "%d discarded packets may skew results! Discarded %.1f %% of all "
            "requests; theoretical worst case %.1f %% loss if all discarded packets "
            "happened to be in one %d ms sample",
            stats_sum['discarded'],
            proportion_all_perc,
            proportion_one_sec_perc,
            header["stats_interval"],
        )

    timespan = (stats_sum["until"] - stats_sum["since"]) / 1000
    qps = stats_sum["queries"] / timespan
    name = os.path.splitext(os.path.basename(os.path.normpath(json_path)))[0]
    label = f"{name} ({pc.siname(qps)} QPS)"
    min_timespan = header.get("stats_interval", 1000) / 2

    if not args.skip_total:
        plot_response_rate(ax, stats_periodic, label, min_timespan=min_timespan, color=json_color)

    draw_rcodes = set(args.rcode or [])
    sum_rcodes = set(args.sum_rcodes or [])
    if args.rcodes_above_pct is not None:
        threshold = stats_sum['responses'] * args.rcodes_above_pct / 100
        rcodes_above_limit = set(
            rcode
            for rcode, cnt in stats_sum.get("response_rcodes", {}).items()
            if cnt > threshold
        )
        draw_rcodes = draw_rcodes.union(rcodes_above_limit)

    if draw_rcodes:
        if len(args.json_file) > 1:
            # same color for all rcodes from one JSON
            cur_rcode_colors = collections.defaultdict(lambda: json_color)
        else:
            # single JSON - different color for each RCODE
            cur_rcode_colors = pc.RCODE_COLORS
        for rcode in draw_rcodes:
            if rcode not in pc.RCODES:
                logging.error("Unsupported RCODE: %s", rcode)
                continue

            symbol = pc.RCODE_MARKERS.get(rcode, rcode)
            eval_func = rcode_rate(rcode)
            rcode_label = f"{label} {rcode}"

            plot_response_rate(
                ax,
                stats_periodic,
                rcode_label,
                eval_func=eval_func,
                min_timespan=min_timespan,
                min_rate=args.ignore_rcodes_rate_pct,
                marker=f"${symbol}$",
                color=cur_rcode_colors[rcode],
            )

    if sum_rcodes:
        eval_func = rcode_rate(sum_rcodes)

        sum_label = " ".join(sum_rcodes)
        plot_response_rate(
            ax,
            stats_periodic,
            f"{label} {sum_label}",
            eval_func=eval_func,
            min_timespan=min_timespan,
            marker="$\\sum$",
            color=json_color,
        )


if __name__ == "__main__":
    main()
