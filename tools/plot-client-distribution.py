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
from cycler import cycler
import matplotlib

matplotlib.use("Agg")
import matplotlib.colors
from matplotlib.lines import Line2D
import matplotlib.pyplot as plt

import mplhlpr.styles

SCALE_MAGIC = 10000


def init_plot(title):
    _, ax = plt.subplots()

    ax.set_xscale("log")
    ax.set_yscale("log")

    ax.grid(True, which="major")
    ax.grid(True, which="minor")
    ax.set_ylim(0.00009, 110)

    ax.set_xlabel("Number of queries per client")
    ax.set_ylabel("Percentage of clients")
    mplhlpr.styles.ax_set_title(ax, title)

    colors = [
        matplotlib.colors.to_rgba(c)
        for c in plt.rcParams["axes.prop_cycle"].by_key()["color"]
    ]
    default_cycler = cycler(hatch=[None, "++", "xx", "oo"]) * cycler(facecolor=colors)

    return ax, default_cycler


def count_client_queries(
    filename: str,
) -> Dict[str, int]:
    with open(filename, newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(
            csvfile, delimiter=",", quotechar='"', quoting=csv.QUOTE_NONNUMERIC
        )
        return {row["ip"]: int(row["packets"]) for row in reader}


def plot_client_query_scatter(ax, clients: Dict[str, int], plot_props):
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
        if len(samples) == 0:  # an empty interval
            logging.info("  [%d-%d) queries per client: 0 clients", lmin, lmax)
        else:
            sanity_nsamples += len(samples)
            x.append(statistics.mean(samples))
            y.append(len(samples) / len(data) * 100)
            s.append(sum(samples))
            logging.info(
                "  [%d-%d) queries per client: %d (%.2f %%) clients; %d queries total",
                lmin,
                lmax,
                len(samples),
                y[-1],
                int(s[-1]),
            )
        lmin = lmax
        lmax *= step_multiplier

    assert sanity_nsamples == len(data)
    logging.info("  total: %d clients; %d queries", len(data), int(sum(s)))

    # normalize size
    s_tot = sum(s)
    s = [size * (SCALE_MAGIC / s_tot) for size in s]

    ax.scatter(x, y, s, alpha=0.5, **plot_props)
    ax.scatter(x, y, linewidth=1, marker="x", alpha=0.5, **plot_props)


def main():
    logging.basicConfig(
        format="%(asctime)s %(levelname)8s  %(message)s", level=logging.DEBUG
    )
    logger = logging.getLogger("matplotlib")
    # set WARNING for Matplotlib
    logger.setLevel(logging.WARNING)

    mplhlpr.styles.configure_mpl_styles()

    parser = argparse.ArgumentParser(
        description="Analyze query distribution among clients in input pcap"
    )
    parser.add_argument(
        "csv",
        nargs="+",
        help="CSV(s) to visualize (output from count-packets-per-ip.lua)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="clients.svg",
        help="output filename (default: clients.svg)",
    )
    args = parser.parse_args()

    ax, plot_cycler = init_plot("Query distribution among clients")
    handles = []
    lines = []
    labels = []

    if len(plot_cycler) < len(args.csv):
        logging.critical(
            "more than %d input files at once is not supported, got %d",
            len(plot_cycler),
            len(args.csv),
        )
        sys.exit(3)
    for plot_props, csv_inf in zip(plot_cycler, args.csv):
        label = os.path.basename(csv_inf)
        logging.info("Processing: %s", label)
        try:
            clients_qps = count_client_queries(csv_inf)
        except FileNotFoundError as exc:
            logging.critical("%s", exc)
            sys.exit(1)
        except Exception as exc:
            logging.critical("uncaught exception: %s", exc)
            logging.debug(traceback.format_exc())
            sys.exit(1)
        else:
            labels.append(label)
            lines.append(matplotlib.patches.Patch(**plot_props))
            handles.append(plot_client_query_scatter(ax, clients_qps, plot_props))

    ax.legend(lines, labels, loc="lower left")
    plt.savefig(args.output)
    sys.exit(0)


if __name__ == "__main__":
    main()
