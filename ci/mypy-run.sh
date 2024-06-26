#!/usr/bin/env bash
set -e

# Find Python scripts
FILES=$(find . \
	-path './ci' -prune -o \
	-path './.git' -prune -o \
	-path './replay/dnssim/vendor' -prune -o \
	-name '*.py' -print)

python3 -m mypy \
	--explicit-package-bases \
	--ignore-missing-imports ${FILES}
