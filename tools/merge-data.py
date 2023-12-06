#!/usr/bin/env python3

import argparse
import json
import logging
import os
import sys
import traceback


JSON_VERSION = 20200527
DEFAULT_FILENAME = "shotgun-all.json"


class VersionError(RuntimeError):
    def __init__(self):
        super().__init__(
            "Older formats of JSON data aren't supported. "
            "Use older tooling or re-run the tests with newer shotgun."
        )


class MismatchData(RuntimeError):
    pass


class MissingData(RuntimeError):
    def __init__(self, field):
        super().__init__(
            'Field "{field}" is missing in one or more files.'.format(field=field)
        )


class MergeFailed(RuntimeError):
    def __init__(self, field):
        super().__init__('Failed to merge field "{field}".'.format(field=field))


def first(iterable):
    assert len(iterable) >= 1
    return iterable[0]


def same(iterable):
    assert len(iterable) >= 1
    if not all(val == iterable[0] for val in iterable):
        raise MismatchData
    return iterable[0]


def merge_latency(iterable):
    assert len(iterable) >= 1
    latency = list(iterable[0])
    for latency_data in iterable[1:]:
        if len(latency_data) != len(latency):
            raise MismatchData
        for i, _ in enumerate(latency_data):
            latency[i] += latency_data[i]
    return latency


DATA_STRUCTURE_STATS = {
    "since_ms": min,
    "until_ms": max,
    "requests": sum,
    "ongoing": sum,
    "answers": sum,
    "conn_active": sum,
    "conn_resumed": sum,
    "conn_tcp_handshakes": sum,
    "conn_quic_handshakes": sum,
    "conn_quic_0rtt_loaded": sum,
    "conn_handshakes_failed": sum,
    "rcode_noerror": sum,
    "rcode_formerr": sum,
    "rcode_servfail": sum,
    "rcode_nxdomain": sum,
    "rcode_notimp": sum,
    "rcode_refused": sum,
    "rcode_yxdomain": sum,
    "rcode_yxrrset": sum,
    "rcode_nxrrset": sum,
    "rcode_notauth": sum,
    "rcode_notzone": sum,
    "rcode_badvers": sum,
    "rcode_badkey": sum,
    "rcode_badtime": sum,
    "rcode_badmode": sum,
    "rcode_badname": sum,
    "rcode_badalg": sum,
    "rcode_badtrunc": sum,
    "rcode_badcookie": sum,
    "rcode_other": sum,
    "latency": merge_latency,
}


def merge_stats(iterable):
    return merge_fields(DATA_STRUCTURE_STATS, iterable)


def merge_periodic_stats(iterable):
    out = []

    for i in range(max([len(stats_periodic) for stats_periodic in iterable])):
        to_merge = []
        for stats_periodic in iterable:
            try:
                stats = stats_periodic[i]
            except IndexError:
                continue
            else:
                to_merge.append(stats)
        out.append(merge_stats(to_merge))

    return out


DATA_STRUCTURE_ROOT = {
    "version": same,
    "merged": lambda x: True,
    "stats_interval_ms": same,
    "timeout_ms": same,
    "discarded": sum,
    "stats_sum": merge_stats,
    "stats_periodic": merge_periodic_stats,
}


def merge_fields(fields, thread_data):
    out = {}
    for field, merge_func in fields.items():
        try:
            field_data = [data[field] for data in thread_data]
        except KeyError as exc:
            raise MissingData(field) from exc
        try:
            out[field] = merge_func(field_data)
        except Exception as exc:
            raise MergeFailed(field) from exc
    return out


def merge_data(thread_data):
    assert len(thread_data) >= 1
    try:
        if thread_data[0]["version"] != JSON_VERSION:
            raise VersionError
    except KeyError as exc:
        raise VersionError from exc
    return merge_fields(DATA_STRUCTURE_ROOT, thread_data)


def main():
    logging.basicConfig(
        format="%(asctime)s %(levelname)8s  %(message)s", level=logging.DEBUG
    )

    parser = argparse.ArgumentParser(description="Merge JSON shotgun results")

    parser.add_argument("json_file", nargs="+", help="Paths to per-thread JSON results")
    parser.add_argument(
        "-o", "--output", default=DEFAULT_FILENAME, help="Output JSON file"
    )
    args = parser.parse_args()

    outpath = args.output
    if outpath == DEFAULT_FILENAME:
        outpath = os.path.join(os.path.dirname(args.json_file[0]), outpath)

    try:
        thread_data = []
        for path in args.json_file:
            with open(path) as f:
                thread_data.append(json.load(f))

        merged = merge_data(thread_data)

        with open(outpath, "w") as f:
            json.dump(merged, f)
        logging.info("DONE: merged shotgun results saved as %s", outpath)
    except (FileNotFoundError, VersionError) as exc:
        logging.critical("%s", exc)
        sys.exit(1)
    except (MergeFailed, MissingData) as exc:
        logging.debug(traceback.format_exc())
        logging.critical("%s", exc)
        sys.exit(1)
    except Exception as exc:
        logging.critical("uncaught exception: %s", exc)
        logging.debug(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
