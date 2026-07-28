#!/bin/bash
set -exuo pipefail

# Every combination of the matrix is a *clean out-of-tree* build, and
# autoconf refuses those while the source directory itself still carries
# a config.status.  A CI checkout is clean; a developer running this job
# by hand on a working tree usually is not.
if [ -f config.status ] || [ -f Makefile ]; then
	make distclean || true
fi
if [ -f config.status ]; then
	echo "ERROR: source directory is still configured;" \
	     "run 'make distclean' by hand first." >&2
	exit 1
fi

./bootstrap
