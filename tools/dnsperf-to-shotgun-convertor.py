#!/usr/bin/python
import argparse
import json

def convert_header(header):
    def convert_timeformat(filets):
        return filets * 1000 // header['time_units_per_sec']  # ms

    out = header.copy()
    out['version'] = 20200527
    out['stats_periodic'] = []
    out['timeout_ms'] = convert_timeformat(header['timeout'])
    out['stats_interval_ms'] = convert_timeformat(header['stats_interval'])
    out['discarded'] = 0  # TODO
    return out

def convert(filename):
    def convert_timeformat(filets):
        return filets * 1000 // out['time_units_per_sec']  # ms
    out = {}
    with open(filename, 'r') as inf:
        for line in inf:
            onedict = json.loads(line)
            if onedict['type'] == 'header':
                out.update(convert_header(onedict))
            elif onedict['type'] == 'stats_periodic':
                onedict['since_ms'] = convert_timeformat(onedict['since'])
                onedict['until_ms'] = convert_timeformat(onedict['until'])
                out['stats_periodic'].append(onedict)
            elif onedict['type'] == 'stats_sum':
                onedict['since_ms'] = convert_timeformat(onedict['since'])
                onedict['until_ms'] = convert_timeformat(onedict['until'])
                out['stats_sum'] = onedict
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", nargs='+')
    args = parser.parse_args()
    for filename in args.file:
        out = convert(filename)
        with open(f'{filename}.json', 'w') as outf:
            json.dump(out, outf)


if __name__ == "__main__":
    main()

