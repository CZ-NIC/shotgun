#!/usr/bin/env bash
set -e

# Find Python modules and standalone Python scripts
FILES=$(find . \
	-type d -exec test -e '{}/__init__.py' \; -print -prune -o \
	-path './ci' -prune -o \
	-path './.git' -prune -o \
	-name '*.py' -print)

python3 -m pylint -j 0 --rcfile pylintrc ${FILES}
