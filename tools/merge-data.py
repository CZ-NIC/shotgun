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


class UnexpectedType(RuntimeError):
    def __init__(self, field):
        super().__init__(f'JSON type "{field}" is not supported by this script')


class ThreadMismatch(RuntimeError):
    def __init__(self):
        super().__init__('Thread files have different structure.')


class MissingData(RuntimeError):
    def __init__(self, field):
        super().__init__(f'Field "{field}" is missing in one or more files.')


class MergeFailed(RuntimeError):
    def __init__(self, field):
        super().__init__(f'Failed to merge field "{field}".')


def first(iterable):
    assert len(iterable) >= 1
    return iterable[0]


def same(iterable):
    assert len(iterable) >= 1
    if not all(val == iterable[0] for val in iterable):
        raise MismatchData
    return iterable[0]


def merge_latency_data(iterable):
    assert len(iterable) >= 1
    latency = list(iterable[0])
    for latency_data in iterable[1:]:
        if len(latency_data) != len(latency):
            raise MismatchData
        for i, _ in enumerate(latency_data):
            latency[i] += latency_data[i]
    return latency

def merge_response_rcodes(iterable):
    merged = {}
    for rcodes in iterable:
        for rcode, count in rcodes.items():
            merged[rcode] = merged.get(rcode, 0) + count
    return merged

def merge_response_latency(iterable):
    merged_data = merge_latency_data([entry["counts"] for entry in iterable])
    result = {"counts": merged_data}
    return result

def merge_conn_info(iterable):
    assert len(iterable) >= 1
    merged = {}
    for conn_info in iterable:
        if "type" not in merged:
            merged["type"] = conn_info.get("type")

        if "handshakes" in conn_info:
            merged["handshakes"] = merged.get("handshakes", 0) + conn_info["handshakes"]
        if "handshakes_failed" in conn_info:
            merged["handshakes_failed"] = merged.get("handshakes_failed", 0) + conn_info["handshakes_failed"]

        if "resumption" in conn_info:
            if "resumption" not in merged:
                merged["resumption"] = {}
            merged["resumption"]["established"] = merged["resumption"].get("established", 0) + conn_info["resumption"]["established"]

        if "zero_rtt" in conn_info:
            if "zero_rtt" not in merged:
                merged["zero_rtt"] = {}
            merged["zero_rtt"]["loaded"] = merged["zero_rtt"].get("loaded", 0) + conn_info["zero_rtt"]["loaded"]
            merged["zero_rtt"]["sent"] = merged["zero_rtt"].get("sent", 0) + conn_info["zero_rtt"]["sent"]
            merged["zero_rtt"]["answered"] = merged["zero_rtt"].get("answered", 0) + conn_info["zero_rtt"]["answered"]

    return merged

DATA_STRUCTURE_STATS = {
    "runid": same,
    "type": same,
    "since": min,
    "until": max,
    "queries": sum,
    "responses": sum,
    "timeouts": sum,
    "discarded": sum,
    "response_rcodes": merge_response_rcodes,
    "response_latency": merge_response_latency,
    "conn_active": sum,
    "conn_info": merge_conn_info
}

OPTIONAL_STATS_FIELDS = {"response_rcodes", "response_latency", "conn_info"}


def merge_stats(iterable):
    out = {}
    for field, merge_func in DATA_STRUCTURE_STATS.items():
        field_data = [data[field] for data in iterable if field in data]
        if not field_data:
            raise MissingData(field)
        try:
            out[field] = merge_func(field_data)
        except Exception as exc:
            raise MergeFailed(field) from exc
    return out


DATA_STRUCTURE_HEADER = {
    "runid": first,
    "type": same,
    "schema_version": same,
    "generator": same,
    "generator_version": same,
    "time_units_per_sec": same,
    "stats_interval": same,
    "timeout": same,
    "latency_bucket_boundaries": same
}


def merge_headers(iterable):
    out = {}
    for field, merge_func in DATA_STRUCTURE_HEADER.items():
        try:
            field_data = [data[field] for data in iterable]
        except KeyError as exc:
            raise MissingData(field) from exc
        try:
            out[field] = merge_func(field_data)
        except Exception as exc:
            raise MergeFailed(field) from exc
    out["merged"] = True
    return out


def merge_data(thread_data):
    paths = thread_data
    handles = [open(path, encoding="utf-8") for path in paths]
    try:
        yield from _merge_streams(handles)
    finally:
        for f in handles:
            f.close()


def read_next(handles):
    results = []
    for f in handles:
        line = f.readline()
        if not line:
            return None
        results.append(json.loads(line.strip()))
    return results


def _merge_streams(handles):
    while True:
        objects = read_next(handles)
        if objects is None:
            break

        types = {o.get("type") for o in objects}
        if len(types) != 1:
            raise ThreadMismatch()
        t = types.pop()
        if t == "header":
            merged_header = merge_headers(objects)
            merged_header["merged"] = True
            yield merged_header
        elif t == "stats_periodic":
            merged = merge_stats(objects)
            yield merged
        elif t == "stats_sum":
            merged = merge_stats(objects)
            yield merged
        else:
            raise UnexpectedType(t)


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
        with open(outpath, "w", encoding="utf-8") as out:
            for obj in merge_data(args.json_file):
                out.write(json.dumps(obj) + "\n")
        logging.info("DONE: merged shotgun results saved as %s", outpath)
    except (FileNotFoundError, UnexpectedType, ThreadMismatch) as exc:
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
