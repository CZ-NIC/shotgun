#!/usr/bin/python3
import argparse
import os
from pathlib import Path
import random
import sys


def positive_int(val):
    i = int(val)
    if i <= 0:
        raise ValueError("must be greater than 0")
    return i


def readable_directory(path):
    po = Path(path)
    if not po.is_dir():
        raise ValueError("must be path to directory")
    return po


def main():
    parser = argparse.ArgumentParser(
        description="Merge subset of PCAP chunks on the fly and write result to stdout"
    )

    parser.add_argument(
        "nchunks",
        type=positive_int,
        help="Number of chunks to randomly select from source_dirs and merge",
    )
    parser.add_argument(
        "source_dirs",
        nargs="+",
        type=readable_directory,
        help="Paths to directories with PCAP chunks",
    )
    parser.add_argument(
        "--seed",
        default=0,
        type=int,
        help="Randomization seed (default: 0); use negative value to turn off randomization",
    )
    args = parser.parse_args()

    # reproducible pseudorandomness
    random.seed(args.seed, version=2)

    pcaps = []
    for dir_path in args.source_dirs:
        pcaps.extend(
            str(path)
            for path in dir_path.glob("**/*")
            if path.is_file() or path.is_fifo()
        )

    if args.nchunks > len(pcaps):
        sys.exit(f"{args.nchunks} chunks requested but only {len(pcaps)} available")

    pcaps.sort()
    if args.seed >= 0:
        random.shuffle(pcaps)
    mergecap_args = ["mergecap", "-F", "pcap", "-w", "-"]
    mergecap_args.extend(pcaps[: args.nchunks])

    sys.stderr.write(f"merging {args.nchunks} chunks into PCAP stream on stdout\n")
    sys.stderr.write(f"executing merge command: {mergecap_args}\n")
    sys.stderr.flush()

    os.execvp("mergecap", mergecap_args)


if __name__ == "__main__":
    main()
