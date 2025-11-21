#!/usr/bin/env python3

import argparse
import copy
import collections
import datetime
import ipaddress
import logging
import math
import os
import shutil
import signal
import subprocess
import sys
from typing import Any, Dict, List, Optional, Set

from jinja2 import Environment, FileSystemLoader
import toml


# [defaults.traffic] fields that will be supplied to every sender config as default if set
DEFAULT_TRAFFIC_FIELDS = [
    "timeout_s",
    "handshake_timeout_s",
    "idle_timeout_s",
    "gnutls_priority",
    "zero_rtt",
    "http_method",
    "dns_port",
    "dot_port",
    "doh_port",
    "doq_port",
    "server",
    "channel_size",
    "max_clients",
    "batch_size",
]

# Protocol aliases are translated into specific dnssim functions.
PROTOCOL_FUNCS = {
    "udp": "udp",
    "tcp": "tcp",
    "dot": "tls",
    "doh": "https2",
    "doq": "quic",
    "tls": "tls",
    "https2": "https2",
    "quic": "quic",
}


# CPU factor is used along with weight to distribute senders to threads while
# achieving optimal performance.
CPU_FACTORS = {
    "udp": 1,
    "tcp": 2,
    "tls": 3,
    "https2": 3,
    "quic": 3,
}

# Maps protocol functions to keywords selecting the port number.
PROTOCOL_FUNC_PORTS = {
    "udp": "dns_port",
    "tcp": "dns_port",
    "tls": "dot_port",
    "https2": "doh_port",
    "quic": "doq_port",
}

DIR = os.path.dirname(os.path.realpath(__file__))
CONFIG_DIR = os.path.join(DIR, "configs")
REPLAY_DIR = os.path.join(DIR, "replay")
SHOTGUN_PATH = os.path.join(REPLAY_DIR, "shotgun.lua")

OUTDIR_DEFAULT_PREFIX = "/var/tmp/shotgun"

JINJA_ENV = Environment(loader=FileSystemLoader(REPLAY_DIR))


def load_config(confname: str) -> Dict[str, Any]:
    def get_config_path(confname: str) -> Optional[str]:
        if os.path.isfile(confname):
            return confname
        confname = os.path.join(CONFIG_DIR, confname + ".toml")
        if os.path.isfile(confname):
            return confname
        return None

    path = get_config_path(confname)
    if path is None:
        raise FileNotFoundError(f'config file not found: "{confname}"')

    return {**toml.load(path)}


def fill_config_defaults(config: Dict[str, Any]) -> None:
    for name, conf in config["traffic"].items():
        if not isinstance(conf, dict):
            raise RuntimeError(f"config error: traffic.{name} is not a table")
        conf.setdefault("name", name)
        protocol = conf["protocol"]
        try:
            conf.setdefault("protocol_func", PROTOCOL_FUNCS[protocol])
        except KeyError as e:
            raise RuntimeError(
                f'config error: unknown protocol "{protocol}" in [traffic.{name}]'
            ) from e
        conf.setdefault("cpu_factor", CPU_FACTORS[conf["protocol_func"]])
        conf.setdefault("weight", 1)


def bind_net_to_ips(bind_net: Optional[List[str]]) -> List[str]:
    ips: Set[str] = set()
    if bind_net is None:
        return []
    for entry in bind_net:
        try:
            net = ipaddress.ip_network(entry)
        except ValueError as e:
            raise RuntimeError(
                f"bind_net: {entry} doesn't represent valid net or address"
            ) from e
        hosts = set({str(host) for host in net.hosts()})
        if hosts:
            ips = ips.union(hosts)
        else:  # workaround for missing /32 or /128 support, Python issue #28577
            ips.add(str(net.network_address))
    return list(ips)


def create_luaconfig(config: Dict[str, Any], threads: Dict[str, int], args: Any) -> str:
    data = {
        "verbosity": args.verbosity,
        "threads": [],
    }
    try:
        data["stop_after_s"] = config["input"]["stop_after_s"]
    except KeyError:
        pass

    try:
        data["pcap"] = config["input"]["pcap"]
    except KeyError:
        if not args.read:
            raise RuntimeError("pcap must be set, use -r/--read") from None
        data["pcap"] = args.read

    # FIXME: IP assignment could be weight-based to be more precise (number of
    # threads scales also by cpu_factor, which is irrelevant for IP distribution).
    # Dependening on the number of threads, up to -T IPs could be unused, this
    # could also be optimized.
    ips = bind_net_to_ips(args.bind_net)
    thr_total = sum(threads.values())
    ips_per_thread = math.floor(len(ips) / thr_total)
    if (
        ips_per_thread == 0 and len(ips) > 0
    ):  # less IPs than threads - share the same IPs
        ips_per_thread = len(ips)
        ips *= thr_total

    for kind, count in threads.items():
        thrconf = copy.deepcopy(config["traffic"][kind])
        for key in DEFAULT_TRAFFIC_FIELDS:
            try:
                thrconf.setdefault(key, config["defaults"]["traffic"][key])
            except KeyError:
                pass

        if "server" not in thrconf:
            if args.server is None:
                raise RuntimeError("server must be set, use -s/--server")
            thrconf.setdefault("server", args.server)

        datadir = os.path.join(args.outdir, "data", kind)
        os.makedirs(datadir)

        thrconf.setdefault("dns_port", args.dns_port)
        thrconf.setdefault("dot_port", args.dot_port)
        thrconf.setdefault("doh_port", args.doh_port)
        thrconf.setdefault("doq_port", args.doq_port)

        thrconf["target_ip"] = thrconf["server"]
        thrconf["target_port"] = thrconf[PROTOCOL_FUNC_PORTS[thrconf["protocol_func"]]]
        thrconf["weight"] = math.ceil(
            1000 * thrconf["weight"] / count
        )  # convert to integer

        for i in range(count):
            instconf = copy.deepcopy(thrconf)
            instconf["name"] = f"{kind}-{i+1:02d}"
            fname = os.path.join(datadir, instconf["name"]) + ".json"
            instconf["output_file"] = fname
            instconf["bind_ips"] = []
            for _ in range(ips_per_thread):
                instconf["bind_ips"].append(ips.pop())
            data["threads"].append(instconf)

    confdir = os.path.join(args.outdir, ".config")
    os.mkdir(confdir)

    template = JINJA_ENV.get_template("luaconfig.lua.j2")
    confpath = os.path.join(confdir, "luaconfig.lua")
    with open(confpath, "w", encoding="utf-8") as f:
        f.write(template.render(data))
    logging.debug("luaconfig.lua written to: %s", confpath)
    return confpath


def assign_threads(config: Dict[str, Any], nthreads: int) -> Dict[str, int]:
    if nthreads is None:
        raise RuntimeError("number of threads must be specified")

    nsenders = len(config["traffic"])
    if nthreads < nsenders + 1:
        raise RuntimeError(
            f"minimum threads required for this config is {nsenders + 1} (use -T/--threads)"
        )

    nthreads = nthreads - 1  # one main thread for processing the input pcap

    # assign one thread to each sender
    senders: Dict[str, Dict[str, int]] = {}
    for name, conf in config["traffic"].items():
        target_cpu_weight = conf["weight"] * conf["cpu_factor"]
        senders[name] = {"threads": 1, "target_cpu_weight": target_cpu_weight}
    total_cpu_weight = sum(sender["target_cpu_weight"] for sender in senders.values())
    thread_cpu_weight = total_cpu_weight / nthreads
    nthreads = nthreads - nsenders

    # distribute remaining threads by searching which sender has the largest
    # relative difference between cpu_weight and its target_cpu_weight
    rel_cpu_weights = {
        name: (thread_cpu_weight * sender["threads"]) / sender["target_cpu_weight"]
        for name, sender in senders.items()
    }
    for _ in range(nthreads):
        chosen = sorted(rel_cpu_weights.items(), key=lambda x: x[1])[0][0]
        senders[chosen]["threads"] += 1
        rel_cpu_weights[chosen] = (
            thread_cpu_weight * senders[chosen]["threads"]
        ) / senders[chosen]["target_cpu_weight"]

    return {name: sender["threads"] for name, sender in senders.items()}


def make_outdir(outdir: Optional[str], force: bool) -> str:
    if outdir is None:
        ts = round(datetime.datetime.now().timestamp())
        outdir = os.path.join(OUTDIR_DEFAULT_PREFIX, str(ts))
    if os.path.exists(outdir):
        if not os.path.isdir(outdir):
            if force:
                logging.info('Removing existing file at "%s"', outdir)
                os.remove(outdir)
            else:
                raise RuntimeError(
                    "File exists at the specified output directory path, use -f/--force if you wish to remove it"
                )
        if os.path.isdir(outdir) and len(os.listdir(outdir)) != 0:
            if force:
                logging.info('Removing existing directory "%s"', outdir)
                shutil.rmtree(outdir, ignore_errors=True)
            else:
                raise RuntimeError(
                    "Output directory isn't empty, use -f/--force if you wish to remove it"
                )
    if not os.path.exists(outdir):
        os.makedirs(outdir)
    logging.info("Output directory: %s", outdir)
    return outdir


def get_log_level(verbosity: int) -> int:
    if verbosity <= 0:
        return logging.ERROR
    elif verbosity <= 1:
        return logging.WARNING
    elif verbosity <= 3:
        return logging.INFO
    return logging.DEBUG


def run_or_exit(args: List[str], env: Optional[collections.abc.Mapping] = None) -> None:
    try:
        subprocess.run(args, check=True, env=env)
    except subprocess.CalledProcessError as ex:
        if ex.returncode < 0:
            signum = -ex.returncode
            signal_desc = signal.strsignal(signum)
            logging.error("%s (signum %d)", signal_desc, signum)
        sys.exit(ex.returncode)


def run_shotgun(luaconfig: str, env: collections.abc.Mapping) -> None:
    run_or_exit([SHOTGUN_PATH, luaconfig], env)


def list_json_files(directory: str) -> List[str]:
    return [
        os.path.abspath(os.path.join(directory, filename))
        for filename in os.listdir(directory)
        if filename.endswith(".json")
    ]


def merge_data(datadir: str) -> None:
    for filename in os.listdir(datadir):
        fullpath = os.path.abspath(os.path.join(datadir, filename))
        if not os.path.isdir(fullpath):
            continue
        logging.info("Merging data in: %s", fullpath)
        args = [
            os.path.join(DIR, "tools", "merge-data.py"),
            "-o",
            f"{fullpath}.json",
        ]
        args.extend(list_json_files(fullpath))
        run_or_exit(args)


def plot_charts(config: Dict[str, Any], datadir: str) -> None:
    if "charts" not in config:
        return

    workdir = os.path.join(os.path.dirname(datadir), "charts")
    os.makedirs(workdir)
    for name, conf in config["charts"].items():
        if "type" not in conf:
            logging.error('missing "type" for chart.%s', name)
            continue
        logging.info("Plotting %s", name)
        args = [os.path.join(DIR, "tools", f'plot-{conf["type"]}.py')]
        for key, value in conf.items():
            if key == "type":
                continue
            args.append(f"--{key}")
            if isinstance(value, list):
                for item in value:
                    args.append(f"{item}")
            else:
                args.append(f"{value}")
        if "output" not in conf:
            args.extend(["--output", f"{name}.svg"])
        args.extend(list_json_files(datadir))
        try:
            subprocess.run(args, check=True, cwd=workdir)
        except subprocess.CalledProcessError:
            logging.error("chart %s failed", name)
        except FileNotFoundError:
            logging.error('chart type "%s" invalid', conf["type"])


def main():
    parser = argparse.ArgumentParser(
        description="Replay client traffic over the configured protocols"
    )
    parser.add_argument(
        "-c",
        "--config",
        type=str,
        required=True,
        help="traffic configuration TOML (file path or one of defaults: udp, tcp, dot, doh, mixed)",
    )
    parser.add_argument("-r", "--read", help="PCAP with clients")
    parser.add_argument("-s", "--server", help="target server IP")
    parser.add_argument("-O", "--outdir", help="output directory", type=str)
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="overwrite target directory if exists",
    )
    parser.add_argument(
        "-b",
        "--bind-net",
        type=str,
        nargs="*",
        help="range(s) of source addresses to bind to (CIDR)",
    )
    parser.add_argument(
        "-T",
        "--threads",
        type=int,
        default=os.cpu_count(),
        help="number of threads to use (defaults to number of CPUs detected)",
    )
    parser.add_argument(
        "-v", "--verbosity", help="verbosity level (0-5)", type=int, default=2
    )
    parser.add_argument("--dns-port", type=int, default=53, help="port for UDP/TCP DNS")
    parser.add_argument(
        "--dot-port", type=int, default=853, help="port for DNS-over-TLS"
    )
    parser.add_argument(
        "--doh-port", type=int, default=443, help="port for DNS-over-HTTPS"
    )
    parser.add_argument(
        "--doq-port", type=int, default=853, help="port for DNS-over-QUIC"
    )
    parser.add_argument(
        "--preload",
        help="LD_PRELOAD shotgun with the specified libraries (for debugging)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(levelname)8s  %(message)s",
        level=get_log_level(args.verbosity),
    )

    dnssim_env = os.environ.copy()
    if args.preload:
        if "LD_PRELOAD" in dnssim_env:
            dnssim_env["LD_PRELOAD"] = args.preload + " " + dnssim_env["LD_PRELOAD"]
        else:
            dnssim_env["LD_PRELOAD"] = args.preload

    config = load_config(args.config)
    try:
        fill_config_defaults(config)
        threads = assign_threads(config, args.threads)
        args.outdir = make_outdir(args.outdir, args.force)
        logging.info("Thread distribution:")
        logging.info("  (main): 1 thread(s)")
        for kind, count in threads.items():
            logging.info("  %s: %d thread(s)", kind, count)

        luaconfig = create_luaconfig(config, threads, args)
    except KeyError as e:
        raise RuntimeError(f"configuration is missing required key: {e}") from e

    logging.info("Configuration sucessfully created")
    logging.info("Firing shotgun...")
    run_shotgun(luaconfig, dnssim_env)

    datadir = os.path.join(args.outdir, "data")
    merge_data(datadir)
    plot_charts(config, datadir)

    logging.info("FINISHED Results in %s", args.outdir)


if __name__ == "__main__":
    try:
        main()
    except toml.TomlDecodeError as err:
        logging.critical("TOML config syntax error: %s", err)
    except FileNotFoundError as err:
        logging.critical(err)
    except RuntimeError as err:
        logging.critical(err)
    else:
        sys.exit(0)
    sys.exit(1)
