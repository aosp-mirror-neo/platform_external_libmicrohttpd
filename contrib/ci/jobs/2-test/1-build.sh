#!/bin/bash
set -exuo pipefail

# The every-push configuration of TESTING.md P3:
#
#   --enable-asserts --enable-sanitizers=address,undefined
#
# Both halves matter.  mhd_assert() is compiled out of an ordinary build,
# so the invariants the library documents are only actually checked with
# --enable-asserts; and three of the four v1.0.7 findings were memory
# safety defects that ASAN reports on the spot but that an unsanitised
# build happily runs through.  Anything that is not this configuration is
# nightly (see job 3-build-matrix).

./bootstrap
./configure \
    --enable-asserts \
    --enable-sanitizers=address,undefined
make -j"$(nproc)"
