#!/usr/bin/env python3

import argparse
import logging
import os
import sys

# pylint: disable=wrong-import-order,wrong-import-position
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

import mplhlpr.styles

import _plot_common as pc

KIND_SPECS = {
    "active": (
        "Active ({name})",
        lambda: pc.COLOR_ACTIVE,
        lambda stats: stats["conn_active"],
    ),
    "conn_hs": (
        "Handshakes ({name})",
        lambda: pc.COLOR_CONN_HS,
        lambda stats: stats["conn_info"]["handshakes"],
    ),
    "quic_0rtt": (
        "QUIC 0RTT ({name})",
        lambda: pc.COLOR_QUIC_0RTT,
        lambda stats: stats["conn_info"]["zero_rtt"]["loaded"],
    ),
    "quic_0rtt_sent": (
        "QUIC 0RTT sent ({name})",
        lambda: pc.COLOR_QUIC_0RTT_SENT,
        lambda stats: stats["conn_info"]["zero_rtt"]["sent"],
    ),
    "quic_0rtt_answered": (
        "QUIC 0RTT answered ({name})",
        lambda: pc.COLOR_QUIC_0RTT_ANSWERED,
        lambda stats: stats["conn_info"]["zero_rtt"]["answered"],
    ),
    "tls_resumed": (
        "TLS Resumed ({name})",
        lambda: pc.COLOR_TLS_RESUMED,
        lambda stats: stats["conn_info"]["resumption"]["established"],
    ),
    "failed_hs": (
        "Failed Handshakes ({name})",
        lambda: pc.COLOR_FAILED_HS,
        lambda stats: stats["conn_info"]["handshakes_failed"],
    ),
}


def init_plot(title):
    _, ax = plt.subplots()

    ax.set_xlabel("Time [s]")
    ax.set_ylabel("Number of connections")
    mplhlpr.styles.ax_set_title(ax, title)

    ax.grid(True, axis="x", which="major")
    ax.grid(True, axis="y", which="major")
    ax.grid(True, axis="y", which="minor")

    return ax


def plot(ax, data, label, eval_func, min_timespan=0, color=None):
    stats_periodic = data[:-1]
    time_offset = stats_periodic[0]["since"]

    xvalues = []
    yvalues = []
    for stats in stats_periodic:
        timespan = stats["until"] - stats["since"]
        if timespan < min_timespan:
            continue
        time = (stats["until"] - time_offset) / 1000
        xvalues.append(time)
        yvalues.append(eval_func(stats))

    ax.plot(xvalues, yvalues, label=label, color=color)


def plot_selected_kinds(ax, stats_periodic, name, kinds):
    for kind in kinds:
        label_template, color_cycle, eval_func = KIND_SPECS[kind]
        try:
            plot(
                ax,
                stats_periodic,
                label=label_template.format(name=name),
                color=next(color_cycle()),
                eval_func=eval_func,
            )
        except KeyError as e:
            raise RuntimeError(
                f"Missing expected key {e} while plotting {kind!r} stats for {name!r}"
            ) from e


def main():
    logging.basicConfig(
        format="%(asctime)s %(levelname)8s  %(message)s", level=logging.DEBUG
    )
    logger = logging.getLogger("matplotlib")
    # set WARNING for Matplotlib
    logger.setLevel(logging.WARNING)

    mplhlpr.styles.configure_mpl_styles()

    parser = argparse.ArgumentParser(
        description="Plot connections over time from shotgun experiment"
    )

    parser.add_argument("json_file", nargs="+", help="Shotgun results JSON file(s)")
    parser.add_argument(
        "-t", "--title", default="Connections over Time", help="Graph title"
    )
    parser.add_argument(
        "-o", "--output", default="connections.svg", help="Output graph filename"
    )
    parser.add_argument(
        "-k",
        "--kind",
        nargs="+",
        choices=[
            "active",
            "conn_hs",
            "tcp_hs",  # same as conn_hs - backwards compatibility
            "quic_0rtt",
            "quic_0rtt_sent",
            "quic_0rtt_answered",
            "tls_resumed",
            "failed_hs",
        ],
        default=["active", "conn_hs", "tls_resumed", "failed_hs"],
        help="Which data should be rendered",
    )
    args = parser.parse_args()

    # initialize graph
    ax = init_plot(args.title)

    for json_path in args.json_file:
        _, stats_sum, stats_periodic = pc.load_json_lines_file(json_path)

        if stats_sum["discarded"] != 0:
            logging.warning(
                "%d discarded packets may skew results!", stats_sum["discarded"]
            )

        name = os.path.splitext(os.path.basename(os.path.normpath(json_path)))[0]

        plot_selected_kinds(ax, stats_periodic, name, args.kind)

    # set axis boundaries
    ax.set_xlim(xmin=0)
    ax.set_ylim(ymin=0)

    plt.legend()
    plt.savefig(args.output)


if __name__ == "__main__":
    main()
