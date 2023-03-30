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

matplotlib.use("Agg")
import matplotlib.pyplot as plt


JSON_VERSION = 20200527


StatRcode = collections.namedtuple("StatRcode", ["field", "label"])

RCODES = {
    0: StatRcode("rcode_noerror", "NOERROR"),
    1: StatRcode("rcode_formerr", "FORMERR"),
    2: StatRcode("rcode_servfail", "SERVFAIL"),
    3: StatRcode("rcode_nxdomain", "NXDOMAIN"),
    4: StatRcode("rcode_notimp", "NOTIMP"),
    5: StatRcode("rcode_refused", "REFUSED"),
    6: StatRcode("rcode_yxdomain", "YXDOMAIN"),
    7: StatRcode("rcode_yxrrset", "YXRRSET"),
    8: StatRcode("rcode_nxrrset", "NXRRSET"),
    9: StatRcode("rcode_notauth", "NOTAUTH"),
    10: StatRcode("rcode_notzone", "NOTZONE"),
    16: StatRcode("rcode_badvers", "BADVERS"),
    17: StatRcode("rcode_badkey", "BADKEY"),
    18: StatRcode("rcode_badtime", "BADTIME"),
    19: StatRcode("rcode_badmode", "BADMODE"),
    20: StatRcode("rcode_badname", "BADNAME"),
    21: StatRcode("rcode_badalg", "BADALG"),
    22: StatRcode("rcode_badtrunc", "BADTRUNC"),
    23: StatRcode("rcode_badcookie", "BADCOOKIE"),
    100000: StatRcode("rcode_other", "other"),
}

RCODES_TO_NUM = {rcodestat.field: number for number, rcodestat in RCODES.items()}

RCODE_MARKERS = {1: "f", 2: "s", 3: "n", 4: "i", 5: "r", 100000: "?"}

RCODE_COLORS = {
    0: "tab:green",
    1: "tab:brown",
    2: "tab:red",
    3: "tab:blue",
    4: "tab:pink",
    5: "tab:orange",
    6: "tab:purple",
    7: "tab:olive",
    8: "tab:cyan",
    9: "#f0944d",
    10: "#840000",
    11: "#bc13fe",
    12: "#601ef9",
    13: "#bbf90f",
    14: "#fffd01",
    15: "#4f738e",
    16: "#ac7e04",
    17: "#5d1451",
    18: "#fdb0c0",
    19: "#fd3c06",
    20: "#536267",
    21: "#a03623",
    22: "#b7e1a1",
    23: "#0a888a",
    100000: "#000000",
}

sinames = ["", " k", " M", " G", " T"]


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


response_rate = stat_field_rate("answers")


def init_plot(title):
    _, ax = plt.subplots(figsize=(8, 6))

    ax.set_xlabel("Time [s]")
    ax.set_ylabel("Response Rate [%]")
    ax.set_title(title)

    ax.grid(True, axis="x", which="major")

    ax.yaxis.set_major_locator(MultipleLocator(10))
    ax.grid(True, axis="y", which="major")

    ax.yaxis.set_minor_locator(MultipleLocator(2))
    ax.grid(True, axis="y", which="minor", linestyle="dashed", color="#DDDDDD")

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
    data,
    label,
    eval_func=None,
    min_timespan=0,
    min_rate=0,
    marker="o",
    linestyle="--",
    color=None,
):
    stats_periodic = data["stats_periodic"]
    time_offset = stats_periodic[0]["since_ms"]

    if not eval_func:
        eval_func = response_rate

    xvalues = []
    yvalues = []
    for stats in stats_periodic:
        timespan = stats["until_ms"] - stats["since_ms"]
        if timespan < min_timespan:
            continue
        time = (stats["until_ms"] - time_offset) / 1000
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


def rcode_to_int(rcode: str) -> int:
    try:
        return int(rcode)
    except ValueError:
        pass

    try:
        return RCODES_TO_NUM[f"rcode_{rcode.lower()}"]
    except KeyError:
        raise argparse.ArgumentTypeError(f'unsupported rcode "{rcode}"') from None


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

    parser.add_argument("json_file", nargs="+", help="Shotgun results JSON file(s)")
    parser.add_argument(
        "-t", "--title", default="Response Rate over Time", help="Graph title"
    )
    parser.add_argument(
        "-o", "--output", default="response_rate.svg", help="Output graph filename"
    )
    parser.add_argument(
        "-T",
        "--skip-total",
        action="store_const",
        const="True",
        help="Plot line for total response rate (default)",
    )
    parser.add_argument(
        "-r",
        "--rcode",
        nargs="*",
        type=rcode_to_int,
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
        "-s", "--sum-rcodes", nargs="*", type=rcode_to_int, help="Plot sum of RCODE(s)"
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
    with open(json_path) as f:
        data = json.load(f)
    try:
        assert data["version"] == JSON_VERSION
    except (KeyError, AssertionError):
        raise NotImplementedError(
            "Older formats of JSON data aren't supported. "
            "Use older tooling or re-run the tests with newer shotgun."
        ) from None

    if data["discarded"] != 0:
        proportion_all_perc = data["discarded"] / data["stats_sum"]["requests"] * 100
        proportion_one_sec_perc = (
            data["discarded"]
            / min(sample["requests"] for sample in data["stats_periodic"])
            * 100
        )
        logging.warning(
            "%d discarded packets may skew results! Discarded %.1f %% of all "
            "requests; theoretical worst case %.1f %% loss if all discarded packets "
            "happened to be in one %d ms sample",
            data["discarded"],
            proportion_all_perc,
            proportion_one_sec_perc,
            data["stats_interval_ms"],
        )

    timespan = (data["stats_sum"]["until_ms"] - data["stats_sum"]["since_ms"]) / 1000
    qps = data["stats_sum"]["requests"] / timespan
    name = os.path.splitext(os.path.basename(os.path.normpath(json_path)))[0]
    label = "{} ({} QPS)".format(name, siname(qps))
    min_timespan = data["stats_interval_ms"] / 2

    if not args.skip_total:
        plot_response_rate(ax, data, label, min_timespan=min_timespan, color=json_color)

    draw_rcodes = set(args.rcode or [])
    sum_rcodes = set(args.sum_rcodes or [])
    if args.rcodes_above_pct is not None:
        threshold = data["stats_sum"]["answers"] * args.rcodes_above_pct / 100
        rcodes_above_limit = set(
            RCODES_TO_NUM[key]
            for key, cnt in data["stats_sum"].items()
            if key.startswith("rcode_") and cnt > threshold
        )
        draw_rcodes = draw_rcodes.union(rcodes_above_limit)

    if draw_rcodes:
        if len(args.json_file) > 1:
            # same color for all rcodes from one JSON
            cur_rcode_colors = collections.defaultdict(lambda: json_color)
        else:
            # single JSON - different color for each RCODE
            cur_rcode_colors = RCODE_COLORS
        for rcode in draw_rcodes:
            try:
                stat_rcode = RCODES[rcode]
                symbol = RCODE_MARKERS.get(rcode, str(rcode))
            except KeyError:
                logging.error("Unsupported RCODE: %s", rcode)
                continue

            eval_func = stat_field_rate(stat_rcode.field)
            rcode_label = "{} {}".format(label, stat_rcode.label)

            plot_response_rate(
                ax,
                data,
                rcode_label,
                eval_func=eval_func,
                min_timespan=min_timespan,
                min_rate=args.ignore_rcodes_rate_pct,
                marker=f"${symbol}$",
                linestyle="dotted",
                color=cur_rcode_colors[rcode],
            )

    if sum_rcodes:

        def sum_rate(stats):
            return sum(stats[RCODES[ircode].field] for ircode in sum_rcodes)

        eval_func = stat_field_rate(sum_rate)

        sum_label = " ".join(RCODES[ircode].label for ircode in sum_rcodes)
        plot_response_rate(
            ax,
            data,
            f"{label} {sum_label}",
            eval_func=eval_func,
            min_timespan=min_timespan,
            marker="$\\sum$",
            linestyle="dotted",
            color=json_color,
        )


if __name__ == "__main__":
    main()
