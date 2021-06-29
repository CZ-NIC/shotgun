#!/usr/bin/python3

from abc import ABC, abstractmethod
import argparse
import collections
import json
import logging
from pathlib import Path
from pprint import pprint
import re
import sys

def load_json(infile):
    """parse newline separated stream of JSON objects"""
    for line in infile:
        if line:
            #logging.debug('parsing line: %s', line)
            yield json.loads(line)

class StatParser(ABC):
    @abstractmethod
    def parse(self, record):
        """Stateless parser: Parse whole input text an return data items."""
        ...

    @abstractmethod
    def process(self, record):
        """
        Transform one record into zero or more data points in format:
        (metric name, timestamp from, timestamp to, value)
        Point in time metrics: timestamp from == to
        Cumulative metrics: timestamp (from, to]
        For cumulative values, do not yield anything if parser currently
        does not have enough data yet.
        """
        ...

class MemoryCurrent:
    """parse current memory.current value (point in time), stateless"""
    def __init__(self, _):
        pass

    def parse(self, record):
        return int(record['text'])

    def process(self, record):
        yield ('memory.current', record['ts'], record['ts'], self.parse(record))

class SockStat:
    """parse current memory.current value (point in time), stateless"""
    def __init__(self, _):
        pass

    def parse(self, record):
        data = {}  # protocol: metric: value
        for line in record['text'].split('\n'):
            if not line:
                continue
            protocol, metrics_text = line.split(': ')
            metrics = metrics_text.split()
            assert len(metrics) >= 2 and len(metrics) % 2 == 0
            data[protocol] = {}
            for m_idx in range(0, len(metrics), 2):
                metric_name = metrics[m_idx]
                metric_val = int(metrics[m_idx + 1])
                data[protocol][metric_name] = metric_val
        return data

    def process(self, record):
        data = self.parse(record)
        for protocol, metrics in data.items():
            for metric, value in metrics.items():
                yield (f'sockstat.{protocol}.{metric}', record['ts'], record['ts'], data[protocol][metric])

class Pressure:
    """parse cpu/memory/io.some values; cumulative values"""
    regex = re.compile('^some.*total=([0-9]+)$', flags=re.MULTILINE)
    name = None

    def __init__(self, record):
        self.last_ts = record['ts']
        self.last_total = self.parse(record)

    def parse(self, record):
        m = self.regex.search(record['text'])
        assert m, 'pressure file format did not match'
        return int(m.group(1))

    def process(self, record):
        now = record['ts']
        if now == self.last_ts:
            return  # nothing to do, we need another data point

        new_total = self.parse(record)
        percent = (new_total - self.last_total) / (now - self.last_ts) / 1000000 * 100
        yield (f'{self.name}.pressure.some', self.last_ts, now, percent)
        self.last_ts = now
        self.last_total = new_total

class CPUPressure(Pressure):
    name = 'cpu'

class IOPressure(Pressure):
    name = 'io'

class MemoryPressure(Pressure):
    name = 'memory'

class NetworkDevIO:
    def __init__(self, record):
        self.last_ts = record['ts']
        self.last_data = self.parse(record)

    def parse(self, record):
        data = {}  # interface -> tx/rx-stat -> value
        lines = record['text'].split('\n')[2:]
        column_names = ('rx.bytes', 'rx.packets', 'rx.errs', 'rx.drop', 'rx.fifo', 'rx.frame', 'rx.compressed', 'rx.multicast', 'tx.bytes', 'tx.packets', 'tx.errs', 'tx.drop', 'tx.fifo', 'tx.colls', 'tx.carrier', 'tx.compressed')
        for line in lines:
            if not line:
                continue
            in_columns = line.split()
            assert in_columns[0][-1] == ':', 'unexpected interface name'
            iface_name = in_columns[0][:-1]
            assert len(column_names) == len(in_columns) - 1, 'unexpected columns'

            num_columns = list(int(val) for val in in_columns[1:])
            data[iface_name] = dict(zip(column_names, num_columns))
        return data

    def process(self, record):
        now = record['ts']
        if now == self.last_ts:
            return  # nothing to do, we need another data point

        new_data = self.parse(record)
        for iface in new_data:
            if not iface in self.last_data:
                continue  # new iface, no data
            for key in new_data[iface]:
                per_sec = (new_data[iface][key] - self.last_data[iface][key])
                yield (f'net.{iface}.{key}', self.last_ts, now, per_sec)
        self.last_ts = now
        self.last_data = new_data

class CPUStat:
    def __init__(self, record):
        self.last_ts = record['ts']
        self.last_data = self.parse(record)

    def parse(self, record):
        data = {}  # interface -> tx/rx-stat -> value
        lines = record['text'].split('\n')
        line_names = ('usage_usec', 'user_usec', 'system_usec')
        for line in lines:
            if not line:
                continue

            in_columns = line.split()
            assert len(in_columns) == 2, 'unexpected line format'

            name, value = in_columns
            if name not in line_names:
                continue

            data[name] = int(value)
        return data

    def process(self, record):
        now = record['ts']
        if now == self.last_ts:
            return  # nothing to do, we need another data point

        new_data = self.parse(record)
        for key in new_data:
            per_sec = (new_data[key] - self.last_data[key]) / 10**6 / (now - self.last_ts) * 100  # %
            yield (f'cpu.{key.replace("usec", "percent")}', self.last_ts, now, per_sec)
        self.last_ts = now
        self.last_data = new_data

class DiskStat:
    def __init__(self, record):
        self.last_ts = record['ts']
        self.last_data = self.parse(record)
        self.keys_with_abs_values = set(['io.inprogress'])

    def parse(self, record):
        data = {}  # interface -> tx/rx-stat -> value
        lines = record['text'].split('\n')[2:]
        column_names = (#'_major', '_minor', '_device',
                        'read.completed',  # count, cumulative
                        'read.merged', # count, cumulative
                        'read.sectors', # count, cumulative
                        'read.time', # ms, cumulative
                        'write.completed', # count, cumulative
                        'write.merged', # count, cumulative
                        'write.sectors', # count, cumulative
                        'write.time', # ms, cumulative
                        'io.inprogress', # count, at the moment
                        'io.time', # ms, cumulative
                        'io.time.weighted', # count, cumulative
                        'discard.completed', # count, cumulative
                        'discard.merged', # count, cumulative
                        'discard.sectors', # count, cumulative
                        'discard.time', # ms, cumulative
                        'flush.completed', # count, cumulative
                        'flush.time', # ms, cumulative
                        )
        for line in lines:
            if not line:
                continue
            in_columns = line.split()
            disk_name = in_columns[2]
            assert len(column_names) == len(in_columns) - 3, 'unexpected columns'

            num_columns = list(int(val) for val in in_columns[3:])
            data[disk_name] = dict(zip(column_names, num_columns))
        return data

    def process(self, record):
        now = record['ts']
        if now == self.last_ts:
            return  # nothing to do, we need another data point

        new_data = self.parse(record)
        for iface in new_data:
            if not iface in self.last_data:
                continue  # new iface, no data
            for key in new_data[iface]:
                if key in self.keys_with_abs_values:
                    new_val = new_data[iface][key]
                else:  # cumulative metric
                    new_val = (new_data[iface][key] - self.last_data[iface][key])
                yield (f'disk.{iface}.{key}', self.last_ts, now, new_val)
        self.last_ts = now
        self.last_data = new_data

path_parsers = {
    'memory.current': MemoryCurrent,
    'memory.pressure': MemoryPressure,
    'cpu.pressure': CPUPressure,
    'cpu.stat': CPUStat,
    'io.pressure': IOPressure,
    'dev': NetworkDevIO,
    'diskstats': DiskStat,
    'sockstat': SockStat,
    'sockstat6': SockStat,
}

def parse_all(infile):
    """transform input stream of JSON objects to dictionary:
    [cgroup name][metric name] = [(timestamp from, timestamp to, metric value)]
    """
    warned_about = set()
    records = sorted(load_json(infile),
                     key=lambda rec: rec['ts'])
    state = {}  # stateful parsers for individual paths; type: Dict[str, Any]

    # putput: collection name -> stat name -> [ts from, to, value]
    stats = collections.defaultdict(lambda: collections.defaultdict(list))  # Dict[str, Dict[str, List[float, float, float]]]
    for rec in records:
        logging.debug('%f %s', rec['ts'], rec['path'])
        path = Path(rec['path'])
        if path.name not in path_parsers:
            if path.name not in warned_about:
                logging.warning('skipping unsupported key %s', path.name)
                warned_about.add(path.name)
            continue

        if path not in state:  # first time, parser init
            state[path] = path_parsers[path.name](rec)

        for stat_name, ts_from, ts_to, value in state[path].process(rec):
            stats[path.parent.name][stat_name].append((ts_from, ts_to, value))

    return stats


### TODO: extract plotting to a separate script
def init_plot(title):
    _, ax = plt.subplots(figsize=(16, 9))

    ax.set_xlabel('Time [s]')
    #ax.set_ylabel('Packets per sampling period')
    ax.set_title(title)

    ax.grid(True, axis='x', which='both', linestyle='dotted')
    ax.grid(True, axis='y', which='both', linestyle='dotted')
    plt.minorticks_on()

    return ax


def plot(stats, name):
    ### TODO: handle multiple groups with the same set of names (put cgrp name in title & filename?)
    logging.info('plotting %s', name)
    ax = init_plot(name)

    xvalues = []
    yvalues = []
    for _, time_s, rate in stats:
        xvalues.append(time_s)
        yvalues.append(rate)

    ax.plot(xvalues, yvalues, label=name, marker='x', linestyle='dotted')

    plt.savefig(f'{name}.svg')
    plt.close('all')


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    with open(sys.argv[1]) as infile:
        stats = parse_all(infile)
    with open('resmon-extracted.json', 'w') as statfile:
        json.dump(stats, statfile)
    ##pprint(stats)
    #for cgrp in stats:
    #    for stat in stats[cgrp]:
    #        plot(stats[cgrp][stat], stat)
