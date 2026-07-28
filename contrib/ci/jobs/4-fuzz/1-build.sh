#!/bin/bash
set -exuo pipefail

# The in-process fuzzing harnesses of src/fuzz.  See src/fuzz/README and
# src/fuzz/BUILD-INTEGRATION.md.
#
# --enable-fuzzing requires --enable-static (configure enforces it):
# fuzz_str and fuzz_auth_header call functions that are internal to the
# library and therefore not exported from the shared object, so the
# harnesses link against the static archive.  --enable-static is the
# default, but say it explicitly so the job does not silently break if
# that default ever changes.
#
# The harnesses carry three oracles - the sanitizers, an
# MHD_set_panic_func() tripwire and a body-framing oracle - and only the
# first of those needs the sanitizers to be switched on, so this job is
# always built with them.

./bootstrap
./configure \
    --enable-fuzzing \
    --enable-static \
    --enable-asserts \
    --enable-sanitizers=address,undefined
make -j"$(nproc)"
