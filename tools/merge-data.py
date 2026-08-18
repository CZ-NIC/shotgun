#!/usr/bin/env python3

import argparse
import itertools
import json
import logging
import os
import sys
import traceback

SUPPORTED_SCHEMA_VERSION = "20221207"
DEFAULT_FILENAME = "shotgun-all.json"


class VersionError(RuntimeError):
    def __init__(self, field):
        super().__init__(
            f"The schema_version {field} is not supported. "
            "Use older tooling or re-run the tests with newer shotgun. "
            f"(Currently supported version: {SUPPORTED_SCHEMA_VERSION})"
        )


class MismatchData(RuntimeError):
    pass


class UnexpectedType(RuntimeError):
    def __init__(self, field):
        super().__init__(f'JSON type "{field}" is not supported by this script')


class ThreadMismatch(RuntimeError):
    def __init__(self):
        super().__init__("Thread files have different structure.")


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


def version(iterable):
    assert len(iterable) >= 1
    if not all(val == iterable[0] for val in iterable):
        raise MismatchData
    if iterable[0] != SUPPORTED_SCHEMA_VERSION:
        raise VersionError(iterable[0])
    return iterable[0]


def merge_latency_data(iterable):
    assert len(iterable) >= 1
    latency = list(iterable[0])
    for latency_data in iterable[1:]:
        if len(latency_data) != len(latency):
            raise MismatchData
        latency = [sum(pair) for pair in zip(latency, latency_data)]
    return latency


def merge_response_rcodes(iterable):
    merged = {}
    for rcodes in iterable:
        for rcode, count in rcodes.items():
            merged[rcode] = merged.get(rcode, 0) + count
    return merged


def merge_response_latency(iterable):
    merged_data = merge_latency_data([entry["bucket_counts"] for entry in iterable])
    result = {"bucket_counts": merged_data}
    return result


def merge_conn_info(iterable):
    def nested_merge_sum(k):
        if k[0] not in conn_info:
            return
        if len(k) == 1:
            merged[k[0]] = merged.get(k[0], 0) + conn_info[k[0]]
        elif len(k) == 2:
            if k[0] not in merged:
                merged[k[0]] = {}
            merged[k[0]][k[1]] = merged[k[0]].get(k[1], 0) + conn_info[k[0]][k[1]]
        else:
            raise ValueError(f"unsupported key depth: {len(k)} ({k})")

    assert len(iterable) >= 1
    merged = {}

    conn_keys = [
        ["handshakes"],
        ["handshakes_failed"],
        ["resumption", "established"],
        ["zero_rtt", "loaded"],
        ["zero_rtt", "sent"],
        ["zero_rtt", "answered"],
    ]

    for conn_info in iterable:
        if "type" not in merged:
            merged["type"] = conn_info.get("type")

        for keys in conn_keys:
            nested_merge_sum(keys)

    return merged


DATA_STRUCTURE_STATS = {
    "runid": same,
    "type": same,
    "since": min,
    "until": max,
    "queries": sum,
    "ongoing": sum,
    "responses": sum,
    "timeouts": sum,
    "interrupted": sum,
    "unexpected": sum,
    "discarded": sum,
    "response_rcodes": merge_response_rcodes,
    "response_latency": merge_response_latency,
    "conn_active": sum,
    "conn_info": merge_conn_info,
}


OPTIONAL_STATS = {"ongoing", "interrupted", "unexpected", "conn_active"}


def merge_stats(iterable):
    out = {}
    for field, merge_func in DATA_STRUCTURE_STATS.items():
        field_data = [data[field] for data in iterable if field in data]
        if not field_data:
            if field in OPTIONAL_STATS:
                continue
            raise MissingData(field)
        try:
            out[field] = merge_func(field_data)
        except Exception as exc:
            raise MergeFailed(field) from exc
    return out


GAUGE_STATS = {"ongoing", "conn_active"}
SANITY_SKIP_STATS = {"runid", "type"} | GAUGE_STATS
SANITY_COMPARED_STATS = set(DATA_STRUCTURE_STATS) - SANITY_SKIP_STATS


def check_stats_sum(running_sum, stats_sum):
    """
    Differences between the summed stats_periodic records and stats_sum.
    dnssim bumps both accumulators independently, so they must agree.
    """
    one_sided = set(running_sum) ^ set(stats_sum)
    problems = []
    for field in sorted(SANITY_COMPARED_STATS):
        if field in one_sided:
            problems.append(f"{field}: present in only one of stats_periodic/stats_sum")
            continue
        if field not in running_sum:
            continue
        want = running_sum[field]
        got = stats_sum[field]
        if want == got:
            continue
        delta = ""
        if isinstance(want, int) and isinstance(got, int):
            delta = f" (delta {got - want})"
        problems.append(f"{field}: stats_periodic sum {want} != stats_sum {got}{delta}")
    return problems


DATA_STRUCTURE_HEADER = {
    "runid": first,
    "type": same,
    "schema_version": version,
    "generator": same,
    "generator_version": same,
    "generator_params": same,
    "time_units_per_sec": same,
    "stats_interval": same,
    "timeout": same,
    "latency_bucket_boundaries": same,
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
        except VersionError as exc:
            logging.critical("%s", exc)
            sys.exit(1)
        except Exception as exc:
            raise MergeFailed(field) from exc
    out["merged"] = True
    return out


class MergeData:
    """
    Note: All files are opened at the same time and read in full, so the memory usage will be proportional to the size of the files being
    merged. The expected use case doesn't involve a large number of files, so this is a reasonable trade-off for faster merging and simpler
    code. To avoid the issue of too many open files, would mean a significant increase in merge time complexity.
    """

    def __init__(self, thread_data, summarize=False):
        self.paths = thread_data
        self.handles = []
        self.summarize = summarize
        self.problems = []

    def __enter__(self):
        try:
            self.handles = [open(path, encoding="utf-8") for path in self.paths]
        except Exception:
            self._close_all()
            raise
        return self._merge_streams(self.handles)

    def __exit__(self, *_):
        self._close_all()

    def _close_all(self):
        for f in self.handles:
            try:
                f.close()
            except OSError:
                pass

    def _merge_streams(self, handles):
        headers, periodic, sums = self._read_by_type(handles)
        if len(headers) != len(handles):
            raise ThreadMismatch()

        merged_header = merge_headers(headers)
        merged_header["merged"] = True
        yield merged_header

        # Merged period by period rather than line by line: threads tick on
        # their own timers, so one can write a period the others never got to
        # -- a partial one at close, or a whole one when the run is killed
        # abruptly. A period only some threads reached is merged from those
        # threads alone; demanding equal record counts would fail the merge
        # outright over a millisecond of drift.
        running_sum = None
        for objects in itertools.zip_longest(*periodic):
            merged = merge_stats([o for o in objects if o is not None])
            if self.summarize:
                if running_sum is None:
                    running_sum = merged
                else:
                    running_sum = merge_stats([running_sum, merged])
            yield merged

        if self.summarize:
            yield from self._summarize(sums, len(handles), running_sum)
        elif sums:
            # A summary is only written on clean shutdown. Merging a subset of
            # them would silently understate the totals, so it's all or nothing.
            if len(sums) != len(handles):
                raise ThreadMismatch()
            yield merge_stats(sums)

    def _summarize(self, sums, thread_count, running_sum):
        """
        Build stats_sum from the stats_periodic records, verified against the
        thread-written ones when all threads produced them.
        """
        if sums:
            if len(sums) != thread_count:
                # partial set understates the totals
                logging.warning(
                    "only %d of %d threads wrote stats_sum, not comparing",
                    len(sums),
                    thread_count,
                )
            elif running_sum is not None:
                self.problems.extend(check_stats_sum(running_sum, merge_stats(sums)))

        if running_sum is None:
            logging.warning("no stats_periodic records, cannot build stats_sum")
            return
        summary = dict(running_sum)
        summary["type"] = "stats_sum"
        for gauge in GAUGE_STATS:
            if gauge in summary:
                summary[gauge] = 0
        yield summary

    def _read_by_type(self, handles):
        headers = []
        periodic = []
        sums = []
        for handle in handles:
            thread_periodic = []
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                record_type = record.get("type")
                if record_type == "header":
                    headers.append(record)
                elif record_type == "stats_periodic":
                    thread_periodic.append(record)
                elif record_type == "stats_sum":
                    sums.append(record)
                else:
                    raise UnexpectedType(record_type)
            periodic.append(thread_periodic)
        return headers, periodic, sums


def main():
    logging.basicConfig(
        format="%(asctime)s %(levelname)8s  %(message)s", level=logging.DEBUG
    )

    parser = argparse.ArgumentParser(description="Merge JSON shotgun results")

    parser.add_argument("json_file", nargs="+", help="Paths to per-thread JSON results")
    parser.add_argument(
        "-o", "--output", default=DEFAULT_FILENAME, help="Output JSON file"
    )
    parser.add_argument(
        "--summarize",
        action="store_true",
        help="build the stats_sum record by summing the stats_periodic records "
        "instead of merging the ones written by the threads; those are used to "
        "verify the result instead, and a mismatch exits 1",
    )
    args = parser.parse_args()

    outpath = args.output
    if outpath == DEFAULT_FILENAME:
        outpath = os.path.join(os.path.dirname(args.json_file[0]), outpath)

    try:
        merger = MergeData(args.json_file, summarize=args.summarize)
        with open(outpath, "w", encoding="utf-8") as out:
            with merger as to_be_merged_data:
                for obj in to_be_merged_data:
                    out.write(json.dumps(obj) + "\n")
        if merger.problems:
            for problem in merger.problems:
                logging.critical("stats_sum mismatch: %s", problem)
            logging.critical("merged shotgun results still saved as %s", outpath)
            sys.exit(1)
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
