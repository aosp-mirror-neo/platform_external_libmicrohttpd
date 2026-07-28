#!/bin/bash
set -exuo pipefail

# A short, *bounded* fuzz run: this job has to finish in seconds, not
# hours, so that a regression is caught in the pull request rather than
# the next morning.  Long, corpus-accumulating sessions are a different
# thing entirely and are not run here.
#
# MHD_FUZZ_ITERATIONS, MHD_FUZZ_SEED, MHD_FUZZ_MIN_DISCIPLINE and
# MHD_FUZZ_MIN_MEM_LIMIT are ordinary make variables of
# src/fuzz/Makefile.am and can be overridden on the command line.  The
# defaults cover the full discipline and memory-limit range.
#
# Every run is exactly reproducible from (harness, seed), so the seed is
# pinned here.  Point MHD_CI_FUZZ_SEED at $RANDOM in a nightly job if a
# varying seed is wanted; a failure then prints a copy-pasteable replay
# command.

FUZZ_ITERATIONS="${MHD_CI_FUZZ_ITERATIONS:-20000}"
FUZZ_SEED="${MHD_CI_FUZZ_SEED:-1}"

make -C src/fuzz check \
     MHD_FUZZ_ITERATIONS="${FUZZ_ITERATIONS}" \
     MHD_FUZZ_SEED="${FUZZ_SEED}"

# Replay the whole committed seed corpus - including
# corpus/known-findings/ - through every harness.  This is the part that
# proves a fixed crash stays fixed, and it is cheap.
make -C src/fuzz check-corpus
