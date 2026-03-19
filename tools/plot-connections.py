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
        header, stats_sum, stats_periodic = pc.load_json_lines_file(json_path)

        try:
            assert header["schema_version"] == pc.SUPPORTED_SCHEMA_VERSION
        except (KeyError, AssertionError):
            logging.critical(
                "Older formats of JSON data aren't supported. "
                "Use older tooling or re-run the tests with newer shotgun."
            )
            sys.exit(1)

        if stats_sum["discarded"] != 0:
            logging.warning("%d discarded packets may skew results!", stats_sum["discarded"])

        name = os.path.splitext(os.path.basename(os.path.normpath(json_path)))[0]

        if "active" in args.kind:
            plot(
                ax,
                stats_periodic,
                label=f"Active ({name})",
                color=next(pc.COLOR_ACTIVE),
                eval_func=lambda stats: stats["conn_active"],
            )
        if "conn_hs" in args.kind or "tcp_hs" in args.kind:
            plot(
                ax,
                stats_periodic,
                label=f"Handshakes ({name})",
                color=next(pc.COLOR_CONN_HS),
                eval_func=lambda stats: stats["conn_info"]["handshakes"],
            )
        if "quic_0rtt" in args.kind:
            plot(
                ax,
                stats_periodic,
                label=f"QUIC 0RTT ({name})",
                color=next(pc.COLOR_QUIC_0RTT),
                eval_func=lambda stats: stats["conn_info"]["zero_rtt"]["loaded"],
            )
        if "quic_0rtt_sent" in args.kind:
            plot(
                ax,
                stats_periodic,
                label=f"QUIC 0RTT sent ({name})",
                color=next(pc.COLOR_QUIC_0RTT_SENT),
                eval_func=lambda stats: stats["conn_info"]["zero_rtt"]["sent"],
            )
        if "quic_0rtt_answered" in args.kind:
            plot(
                ax,
                stats_periodic,
                label=f"QUIC 0RTT answered ({name})",
                color=next(pc.COLOR_QUIC_0RTT_ANSWERED),
                eval_func=lambda stats: stats["conn_info"]["zero_rtt"]["answered"],
            )
        if "tls_resumed" in args.kind:
            plot(
                ax,
                stats_periodic,
                label=f"TLS Resumed ({name})",
                color=next(pc.COLOR_TLS_RESUMED),
                eval_func=lambda stats: stats["conn_info"]["resumption"]["established"],
            )
        if "failed_hs" in args.kind:
            plot(
                ax,
                stats_periodic,
                label=f"Failed Handshakes ({name})",
                color=next(pc.COLOR_FAILED_HS),
                eval_func=lambda stats: stats["conn_info"]["handshakes_failed"],
            )

    # set axis boundaries
    ax.set_xlim(xmin=0)
    ax.set_ylim(ymin=0)

    plt.legend()
    plt.savefig(args.output)


if __name__ == "__main__":
    main()
