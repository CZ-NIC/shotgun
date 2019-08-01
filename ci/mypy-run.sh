#!/usr/bin/env bash
set -e

# Find Python scripts
FILES=$(find . \
	-path './ci' -prune -o \
	-path './.git' -prune -o \
	-name '*.py' -print)

python3 -m mypy --ignore-missing-imports ${FILES}
