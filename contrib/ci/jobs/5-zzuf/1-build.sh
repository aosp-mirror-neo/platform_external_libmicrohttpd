#!/bin/bash
set -exuo pipefail

# src/testzzuf is only built when RUN_ZZUF_TESTS is true, which requires
# --enable-heavy-tests *and* a usable libcurl (see src/Makefile.am and
# src/testzzuf/README).  The option spelling is
#
#   --enable-heavy-tests[=SCOPE]   with SCOPE in {basic, full}
#
# ("yes" is an alias for "basic", "all" for "full"; anything else is a
# configure error).  "basic" runs 10 client iterations per daemon, "full"
# runs 200 - far too slow for a routine job, so CI uses "basic" and a
# seed sweep instead.
#
# The sanitizer build is the one worth running: enabling sanitizers
# automatically forces the socat relay mode, because zzuf and the
# sanitizers cannot both interpose on the C library.  socat mode is also
# the only mode in which the deterministic chunk-extension self-check
# runs, since it needs an unfuzzed channel to MHD.

./bootstrap
./configure \
    --enable-heavy-tests=basic \
    --enable-asserts \
    --enable-sanitizers=address,undefined
make -j"$(nproc)"
