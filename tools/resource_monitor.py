#!/usr/bin/python3
"""
Periodically dump content of selected /proc and /sys files into stream of JSON-formatted lines.
No data post-processing is done in this script.
Requires cgroups v2.

SPDX-FileCopyrightText: Internet Systems Consortium, Inc. ("ISC")
SPDX-License-Identifier: BSD-2-Clause
"""

import argparse
import asyncio
import json
import logging
from pathlib import Path
import signal
import sys
import time
from typing import List, Optional

# files to watch for each matching cgroup separately
PATHS_CGROUP = ['io.pressure', 'io.stat',
                'cpu.pressure', 'cpu.stat',
                'memory.pressure', 'memory.stat', 'memory.current']

PATHS_SYSTEMWIDE = ['/proc/net/dev', '/proc/net/sockstat', '/proc/net/sockstat6',
                    '/proc/diskstats']
# globals for signal handler
RUNNING = True
PRODUCERS = []  # type: List[asyncio.Task]

def sigint(_signum, _frame):
    """Cancel producers but keep consumer running so no information from queue is lost"""
    global PRODUCERS  # pylint: disable=global-statement
    global RUNNING  # pylint: disable=global-statement

    RUNNING = False
    for task in PRODUCERS:
        task.cancel()

async def read_to_json(fileobj) -> str:
    """Return JSON string with file path, complete content of file, and timestamp."""
    now = time.time()
    text = fileobj.read()
    result = {'ts': now, 'path': fileobj.name, 'text': text}
    return json.dumps(result)

async def watch_file(samples_q: asyncio.Queue, file_path: str, interval: float) -> None:
    """Sample file and put log records into queue."""
    with open(file_path) as fileobj:
        try:
            while True:
                record = await read_to_json(fileobj)
                fileobj.seek(0)
                await samples_q.put(record)
                await asyncio.sleep(interval)
        except asyncio.exceptions.CancelledError:
            return
        except OSError as ex:
            logging.critical('file %s went away, terminating (%s)', fileobj.name, ex)
            sigint(None, None)
            return

async def write_queue(output_fobj, samples_q: asyncio.Queue) -> None:
    """Write individual lines from samples_q into output file"""
    while True:
        record = await samples_q.get()
        print(record, file=output_fobj)
        samples_q.task_done()

async def watch_and_write(interval: float, output: Optional[str], paths: List[str]):
    """Watch all specified files in paralell and periodically dump them into output."""
    samples_q = asyncio.Queue()  # type: asyncio.Queue

    global PRODUCERS  # signal handler, pylint: disable=global-statement
    PRODUCERS = [asyncio.create_task(watch_file(samples_q, path, interval)) for path in paths]
    if output is None:
        output_fobj = sys.stdout
    else:
        output_fobj = open(output, 'w')
    consumer = asyncio.create_task(write_queue(output_fobj, samples_q))

    try:
        await asyncio.gather(*PRODUCERS)
    except asyncio.exceptions.CancelledError:
        pass

    await samples_q.join()  # implicitly awaits consumer
    consumer.cancel()

def get_cgroup_paths(base: str, glob=None):
    """
    Generate paths to statistics files for cgroups matching glob.
    glob=None generates paths for the base cgroup.
    """
    base_path = Path(base)
    if not base_path.is_dir():
        raise NotADirectoryError(f'base cgroup path {base} must be a directory')

    if glob:
        cgrps = list(base_path.glob(glob))
        if len(cgrps) == 0:
            raise ValueError(f'no cgroups found with base dir {base} glob {glob}')
    else:
        cgrps = [base_path]

    for cgrp in cgrps:
        for file in PATHS_CGROUP:
            yield cgrp / file

def wait_for_files(cgroup_base_dir: Path, cgroup_glob: Optional[str]):
    """
    Wait until at least one cgroup matching specified glob exists,
    and return all paths to statistical files.
    """
    while RUNNING:
        try:
            paths = PATHS_SYSTEMWIDE + list(
                        get_cgroup_paths(cgroup_base_dir, cgroup_glob))
            return paths
        except ValueError as ex:
            logging.info('waiting: %s', ex)
            time.sleep(0.1)

def main():
    logging.basicConfig(level=logging.DEBUG, format='%(levelname)s  %(message)s')
    signal.signal(signal.SIGINT, sigint)

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interval", type=float, default=1,
                        help="interval between samples in seconds")
    parser.add_argument("--cgroup-base-dir", type=Path, required=True,
                        help="base cgroup path, e.g. /sys/fs/cgroup/system.slice")
    parser.add_argument("--cgroup-glob", type=str, default=None,
                        help='glob for sub-cgroups to monitor, e.g. docker-*.scope')
    parser.add_argument("--output", type=str, default=None,
                        help="output JSON file; stdout if not specified")
    args = parser.parse_args()

    paths = wait_for_files(args.cgroup_base_dir, args.cgroup_glob)

    if RUNNING:
        logging.debug('gathering content of %s', paths)
        asyncio.run(watch_and_write(args.interval, args.output, paths))

if __name__ == "__main__":
    main()
