#!/bin/bash
set -exuo pipefail

# --enable-coverage adds -fprofile-arcs -ftest-coverage.  Optimisation is
# turned off and debug info on so that the line attribution in the report
# is meaningful.
#
# Heavy tests are enabled because the interesting question this report
# answers is "which parts of the parser does the *whole* suite never
# reach" - and src/testzzuf is a large part of that suite.  Sanitizers
# are deliberately NOT enabled here: they change the code that is
# generated and slow the run down, and the coverage numbers are what this
# job is for.

./bootstrap
./configure CFLAGS="-ggdb -O0" \
    --enable-coverage \
    --enable-asserts \
    --enable-heavy-tests=basic
make -j"$(nproc)"
