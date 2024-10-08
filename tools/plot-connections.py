#!/usr/bin/env python3

import argparse
from itertools import cycle
import json
import logging
import math
import os
import sys

# pylint: disable=wrong-import-order,wrong-import-position
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

import mplhlpr.styles

JSON_VERSION = 20200527

COLOR_ACTIVE = cycle(["royalblue", "cornflowerblue", "darkblue", "lightsteelblue"])
COLOR_CONN_HS = cycle(["forestgreen", "limegreen", "darkgreen", "lightgreen"])
COLOR_QUIC_0RTT = cycle(
    ["darkolivegreen", "darkseagreen", "darkslategray", "greenyellow"]
)
COLOR_QUIC_0RTT_SENT = cycle(["crimson", "brown", "firebrick", "indianred"])
COLOR_QUIC_0RTT_ANSWERED = cycle(["khaki", "moccasin", "peru", "wheat"])
COLOR_TLS_RESUMED = cycle(["orange", "moccasin", "darkorange", "antiquewhite"])
COLOR_FAILED_HS = cycle(["gray", "silver", "black", "gainsboro"])


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
    return f"{(n / 10 ** (3 * siidx)):.0f}{sinames[siidx]}"


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
    stats_periodic = data["stats_periodic"][
        :-1
    ]  # omit the last often misleading datapoint
    time_offset = stats_periodic[0]["since_ms"]

    xvalues = []
    yvalues = []
    for stats in stats_periodic:
        timespan = stats["until_ms"] - stats["since_ms"]
        if timespan < min_timespan:
            continue
        time = (stats["until_ms"] - time_offset) / 1000
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
        try:
            with open(json_path, encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError as exc:
            logging.critical("%s", exc)
            sys.exit(1)

        try:
            assert data["version"] == JSON_VERSION
        except (KeyError, AssertionError):
            logging.critical(
                "Older formats of JSON data aren't supported. "
                "Use older tooling or re-run the tests with newer shotgun."
            )
            sys.exit(1)

        if data["discarded"] != 0:
            logging.warning("%d discarded packets may skew results!", data["discarded"])

        name = os.path.splitext(os.path.basename(os.path.normpath(json_path)))[0]

        if "active" in args.kind:
            plot(
                ax,
                data,
                label=f"Active ({name})",
                color=next(COLOR_ACTIVE),
                eval_func=lambda stats: stats["conn_active"],
            )
        if "conn_hs" in args.kind or "tcp_hs" in args.kind:
            plot(
                ax,
                data,
                label=f"Handshakes ({name})",
                color=next(COLOR_CONN_HS),
                eval_func=lambda stats: stats["conn_handshakes"],
            )
        if "quic_0rtt" in args.kind:
            plot(
                ax,
                data,
                label=f"QUIC 0RTT ({name})",
                color=next(COLOR_QUIC_0RTT),
                eval_func=lambda stats: stats["conn_quic_0rtt_loaded"],
            )
        if "quic_0rtt_sent" in args.kind:
            plot(
                ax,
                data,
                label=f"QUIC 0RTT sent ({name})",
                color=next(COLOR_QUIC_0RTT_SENT),
                eval_func=lambda stats: stats["quic_0rtt_sent"],
            )
        if "quic_0rtt_answered" in args.kind:
            plot(
                ax,
                data,
                label=f"QUIC 0RTT answered ({name})",
                color=next(COLOR_QUIC_0RTT_ANSWERED),
                eval_func=lambda stats: stats["quic_0rtt_answered"],
            )
        if "tls_resumed" in args.kind:
            plot(
                ax,
                data,
                label=f"TLS Resumed ({name})",
                color=next(COLOR_TLS_RESUMED),
                eval_func=lambda stats: stats["conn_resumed"],
            )
        if "failed_hs" in args.kind:
            plot(
                ax,
                data,
                label=f"Failed Handshakes ({name})",
                color=next(COLOR_FAILED_HS),
                eval_func=lambda stats: stats["conn_handshakes_failed"],
            )

    # set axis boundaries
    ax.set_xlim(xmin=0)
    ax.set_ylim(ymin=0)

    plt.legend()
    plt.savefig(args.output)


if __name__ == "__main__":
    main()
