#!/usr/bin/env python3

import argparse
import csv
import logging
import math
import os
import statistics
import sys
from typing import Dict, Tuple

# pylint: disable=wrong-import-order,wrong-import-position
from cycler import cycler
import matplotlib
import matplotlib.colors

matplotlib.use("Agg")
import matplotlib.pyplot as plt

sinames = ["", " k", " M", " G", " T"]


def init_plot(title):
    _, ax = plt.subplots(figsize=(8, 6))

    ax.set_xlabel("Time [s]")
    ax.set_ylabel("Packets per sampling period")
    ax.set_title(title)

    ax.grid(True, axis="x", which="both", linestyle="dotted")
    ax.grid(True, axis="y", which="both", linestyle="dotted")
    plt.minorticks_on()

    default_cycler = cycler(marker=["x", "o", "v", "s"]) * cycler(
        color=list(matplotlib.colors.TABLEAU_COLORS.keys())
    )

    return ax, default_cycler


def plot(ax, data, label, since, until, line_props):
    xvalues = []
    yvalues = []
    for time_s, rate in data.items():
        xvalues.append(time_s)
        yvalues.append(rate)

    ax.plot(xvalues, yvalues, label=label, linestyle="", **line_props)
    ax.set_xlim(xmin=since)
    if math.isfinite(until):
        ax.set_xlim(xmax=until)


def parse_csv(csv_f, since: float, until: float) -> Tuple[float, Dict[float, float]]:
    """
    Parse CSV and return tuple (period, xydata).
    Period between samples is float or NaN if it varies by more than 1 ms.
    XY points are in format Dict[time_s] = period_packets value.
    """
    data = {}
    prev_time = None
    period = None
    for row in csv.DictReader(csv_f):
        now = float(row["time_s"])
        if now < since:
            continue
        if now > until:
            break

        if prev_time is not None:
            if not period:
                period = now - prev_time
            elif not math.isnan(period) and abs(period - abs(now - prev_time)) > 0.001:
                logging.warning(
                    "file %s: sampling period has changed between samples %f and %f",
                    csv_f.name,
                    prev_time,
                    now,
                )
                period = float("nan")  # varies, undefined

        prev_time = now
        data[now] = float(row["period_packets"])

    if not prev_time or not period:
        raise ValueError("at least two data rows are required")

    return period, data


def xyrate_average(
    xyrate: Dict[float, float], orig_period: float, avg_n_samples: int
) -> Dict[float, float]:
    """
    Transform dictionary with [X]=Y values by averaging Y values of avg_n_samples
    consecutive points on X (time) axis.
    """
    orig_start_time = min(xyrate)
    # first sample is at the end of first period
    # our new average should point to the middle of all samples we are averaging over
    avg_start_time = (orig_start_time - orig_period) + (avg_n_samples * orig_period / 2)

    # flaten XY chart to a to sorted list, [0] corresponds to orig_start_time
    orig_rate_vals = list(xyrate[time] for time in sorted(xyrate))
    avg_xy = {}
    avg_idx = 0
    avg_last_idx = int(
        len(orig_rate_vals) / avg_n_samples
    )  # ignore incomplete samples at the end
    while avg_idx < avg_last_idx:
        orig_idx = avg_idx * avg_n_samples
        # beware: indexing from 0, sample 0 is at the end of the first period
        avg_now = avg_start_time + orig_period * (orig_idx + 1)
        avg_xy[avg_now] = statistics.mean(
            orig_rate_vals[orig_idx : orig_idx + avg_n_samples]
        )
        avg_idx += 1
    return avg_xy


def main():
    logging.basicConfig(
        format="%(asctime)s %(levelname)8s  %(message)s", level=logging.DEBUG
    )
    logger = logging.getLogger("matplotlib")
    # set WARNING for Matplotlib
    logger.setLevel(logging.WARNING)

    parser = argparse.ArgumentParser(description="Plot packet rate")

    parser.add_argument(
        "csv_file", nargs="+", help="CSV produced by count-packets-over-time.lua"
    )
    parser.add_argument(
        "-t", "--title", default="Packet rate in traffic sample", help="Graph title"
    )
    parser.add_argument(
        "-o", "--output", default="packet_rate.svg", help="Output graph filename"
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
        "--average", type=float, help="Average samples over specified period (secs)"
    )

    args = parser.parse_args()

    # initialize graph
    ax, plot_props = init_plot(args.title)

    if len(plot_props) < len(args.csv_file):
        logging.critical(
            "more than %d input files at once is not supported, got %d",
            len(plot_props),
            len(args.csv_file),
        )
        sys.exit(3)
    for csv_path, line_props in zip(args.csv_file, plot_props):
        try:
            with open(csv_path) as f:
                period, xyrate = parse_csv(f, args.since, args.until)
        except FileNotFoundError as exc:
            logging.critical("%s", exc)
            sys.exit(1)

        name = os.path.splitext(os.path.basename(os.path.normpath(csv_path)))[0]
        if not math.isnan(period):
            period_str = f"sampling period {round(period, 4)} s"
        else:
            period_str = "variable sampling period"

        if args.average:
            if not math.isfinite(period):
                logging.critical(
                    "file %s: refusing to average samples with a variable "
                    "sampling period",
                    csv_path,
                )
                sys.exit(2)
            n_samples = args.average / period
            if abs(round(n_samples) - n_samples) > 0.0001:
                logging.critical(
                    "file %s: averaging period %f is not an integer multiple "
                    "of the original period %f",
                    csv_path,
                    args.average,
                    period,
                )
                sys.exit(3)
            n_samples = round(n_samples)
            period_str = (
                f"avg {n_samples} samples with period {round(period, 4)} s "
                f"= new period {round(n_samples * period, 4)} s"
            )
            xyrate = xyrate_average(xyrate, period, n_samples)
        plot(ax, xyrate, f"{name} ({period_str})", args.since, args.until, line_props)

    plt.legend()
    plt.savefig(args.output)


if __name__ == "__main__":
    main()
